//! The TLS layer under the websocket, in place of ESP-IDF's `esp_transport_ssl`.
//!
//! It exists for the one thing that transport can't do: resume a session saved
//! before a deep sleep. `esp_transport_ssl` can reuse a session within a boot
//! (`ESP_TRANSPORT_SESSION_TICKET_SAVE`/`USE`), but keeps it in a private
//! struct, so it can be neither written out to survive a sleep nor put back
//! after one. This makes the same esp-tls calls with the session in a
//! [`TlsSession`] the application can reach. See that type for why it matters.
//!
//! TLS 1.3 is the one place it goes further: a 1.3 session ticket arrives
//! after the handshake, so it is saved from a later read, not at connect.
//!
//! It is otherwise a copy of `esp_transport_ssl`'s client path: the same
//! esp-tls connect, the same `select` polls, the same mapping of esp-tls
//! results onto the `esp_tcp_transport_err_t` values the websocket layer reads.
//! The callbacks run on the websocket client's task, which is why nothing here
//! logs on the success path: that task's stack is sized for esp-tls, not for
//! formatting.

#![cfg(target_os = "espidf")]

use core::ffi::{c_char, c_int, CStr};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use esp_idf_svc::sys;

use crate::config::TlsVersion;
use crate::error::Error;
#[cfg(esp_idf_esp_tls_client_session_tickets)]
use crate::tls_session::Handshake;
use crate::tls_session::TlsSession;

/// What a connection needs: how to check the server, how to prove the
/// device, and where the session goes.
pub(crate) struct Settings {
    /// PEM root for the server. `None` uses ESP-IDF's certificate bundle.
    pub server_ca: Option<&'static CStr>,
    /// PEM client certificate and key, for mTLS.
    pub client_certificate: Option<(&'static CStr, &'static CStr)>,
    pub version: TlsVersion,
    pub session: TlsSession,
}

struct Context {
    settings: Settings,
    cfg: sys::esp_tls_cfg_t,
    tls: *mut sys::esp_tls_t,
    sockfd: c_int,
    /// Shared with the [`Stopper`], on the thread that owns the client.
    stopping: Arc<AtomicBool>,
    /// The session being offered, which has to outlive the handshake.
    #[cfg(esp_idf_esp_tls_client_session_tickets)]
    offered: Option<LoadedSession>,
    /// A TLS 1.3 handshake whose ticket hasn't come yet: what it was, for
    /// when the ticket is stored.
    #[cfg(all(esp_idf_esp_tls_client_session_tickets, esp_idf_mbedtls_ssl_proto_tls1_3))]
    ticket_due: Option<Handshake>,
}

/// A new transport, owned by the caller until `esp_transport_destroy`, and
/// the means to cut its waits short.
pub(crate) fn transport(
    settings: Settings,
) -> Result<(sys::esp_transport_handle_t, Stopper), Error> {
    // esp-tls would log a warning and connect with 1.2 anyway, which is not
    // what was asked for, and the warning is easy to miss on a device.
    if settings.version == TlsVersion::Tls13 && !cfg!(esp_idf_mbedtls_ssl_proto_tls1_3) {
        return Err(Error::Transport(
            "TLS 1.3 asked for, but this build has no TLS 1.3 \
             (CONFIG_MBEDTLS_SSL_PROTO_TLS1_3)"
                .into(),
        ));
    }

    let t = unsafe { sys::esp_transport_init() };
    if t.is_null() {
        return Err(Error::Transport("no memory for the TLS transport".into()));
    }

    let stopping = Arc::new(AtomicBool::new(false));
    let context = Box::into_raw(Box::new(Context {
        cfg: base_config(&settings),
        settings,
        tls: ptr::null_mut(),
        sockfd: -1,
        stopping: Arc::clone(&stopping),
        #[cfg(esp_idf_esp_tls_client_session_tickets)]
        offered: None,
        #[cfg(all(esp_idf_esp_tls_client_session_tickets, esp_idf_mbedtls_ssl_proto_tls1_3))]
        ticket_due: None,
    }));

    // Both only fail on a null handle, which was ruled out above. From here
    // on `destroy` owns the context.
    unsafe {
        sys::esp_transport_set_context_data(t, context.cast());
        sys::esp_transport_set_func(
            t,
            Some(connect),
            Some(read),
            Some(write),
            Some(close),
            Some(poll_read),
            Some(poll_write),
            Some(destroy),
        );
        sys::esp_transport_set_default_port(t, 443);
    }

    Ok((t, Stopper(stopping)))
}

fn base_config(settings: &Settings) -> sys::esp_tls_cfg_t {
    let mut cfg = sys::esp_tls_cfg_t::default();

    // esp-tls refuses to connect with no way to verify the server. A named CA
    // wins where there is one; otherwise the roots ESP-IDF bundles, which is
    // what CONFIG_MBEDTLS_CERTIFICATE_BUNDLE is turned on for.
    match settings.server_ca {
        Some(ca) => {
            cfg.__bindgen_anon_1.cacert_buf = ca.as_ptr().cast();
            cfg.__bindgen_anon_2.cacert_bytes = ca.to_bytes_with_nul().len() as _;
        }
        None => cfg.crt_bundle_attach = Some(sys::esp_crt_bundle_attach),
    }

    cfg.tls_version = match settings.version {
        TlsVersion::Any => sys::esp_tls_proto_ver_t_ESP_TLS_VER_ANY,
        TlsVersion::Tls12 => sys::esp_tls_proto_ver_t_ESP_TLS_VER_TLS_1_2,
        TlsVersion::Tls13 => sys::esp_tls_proto_ver_t_ESP_TLS_VER_TLS_1_3,
    };

    // PEM lengths count the NUL, which mbedTLS uses to tell PEM from DER.
    if let Some((certificate, key)) = settings.client_certificate {
        cfg.__bindgen_anon_3.clientcert_buf = certificate.as_ptr().cast();
        cfg.__bindgen_anon_4.clientcert_bytes = certificate.to_bytes_with_nul().len() as _;
        cfg.__bindgen_anon_5.clientkey_buf = key.as_ptr().cast();
        cfg.__bindgen_anon_6.clientkey_bytes = key.to_bytes_with_nul().len() as _;
    }

    cfg
}

unsafe fn context<'a>(t: sys::esp_transport_handle_t) -> Option<&'a mut Context> {
    (sys::esp_transport_get_context_data(t) as *mut Context).as_mut()
}

impl Context {
    fn close(&mut self) {
        if !self.tls.is_null() {
            unsafe { sys::esp_tls_conn_destroy(self.tls) };
            self.tls = ptr::null_mut();
        }
        self.sockfd = -1;
        #[cfg(esp_idf_esp_tls_client_session_tickets)]
        {
            self.offered = None;
        }
        #[cfg(all(esp_idf_esp_tls_client_session_tickets, esp_idf_mbedtls_ssl_proto_tls1_3))]
        {
            self.ticket_due = None;
        }
    }
}

unsafe extern "C" fn connect(
    t: sys::esp_transport_handle_t,
    host: *const c_char,
    port: c_int,
    timeout_ms: c_int,
) -> c_int {
    let Some(ctx) = context(t) else { return -1 };
    ctx.close();
    ctx.stopping.store(false, Ordering::Relaxed);

    ctx.cfg.timeout_ms = timeout_ms;

    #[cfg(esp_idf_esp_tls_client_session_tickets)]
    let offered = ctx.settings.session.saved();
    #[cfg(esp_idf_esp_tls_client_session_tickets)]
    {
        ctx.offered = offered.as_deref().and_then(LoadedSession::load);
        ctx.cfg.client_session = match ctx.offered.as_mut() {
            Some(session) => session.as_mut_ptr(),
            None => ptr::null_mut(),
        };
    }

    let tls = sys::esp_tls_init();
    if tls.is_null() {
        return -1;
    }

    let host_len = CStr::from_ptr(host).to_bytes().len();
    if sys::esp_tls_conn_new_sync(host, host_len as c_int, port, &ctx.cfg, tls) <= 0 {
        report_tls_error(t, tls);
        sys::esp_tls_conn_destroy(tls);

        // A session the server accepted once can still be why this one failed
        // -- the server's certificate changed, or the saved bytes are damaged
        // in a way mbedTLS didn't notice. Offering it again would fail the same
        // way, every time, so the next attempt starts clean.
        #[cfg(esp_idf_esp_tls_client_session_tickets)]
        if offered.is_some() {
            ctx.settings.session.forget();
        }

        return -1;
    }

    if sys::esp_tls_get_conn_sockfd(tls, &mut ctx.sockfd) != sys::ESP_OK {
        sys::esp_tls_conn_destroy(tls);
        return -1;
    }
    ctx.tls = tls;

    if let Some(protocol) = protocol(tls) {
        ctx.settings.session.negotiated(protocol);
    }

    // Known now, kept later: see `read`.
    #[cfg(all(esp_idf_esp_tls_client_session_tickets, esp_idf_mbedtls_ssl_proto_tls1_3))]
    if is_tls13(tls) {
        let handshake = tls13_handshake(tls, offered.is_some());
        ctx.settings.session.record(handshake);
        ctx.ticket_due = Some(handshake);
        return 0;
    }

    #[cfg(esp_idf_esp_tls_client_session_tickets)]
    if let Some(fresh) = save_session(tls) {
        // On resumption mbedTLS keeps the offered session exactly as it was,
        // down to its start time; a full handshake writes a new session ID and
        // a new start time. So the bytes say which this was, without reaching
        // into mbedTLS's private fields for the session ID.
        let handshake = if offered.as_deref() == Some(fresh.as_slice()) {
            Handshake::Resumed
        } else {
            Handshake::Full
        };
        ctx.settings.session.store(fresh, handshake);
    }

    0
}

/// Copy esp-tls's error into the transport's, where the websocket client
/// looks for it when it reports a failure.
unsafe fn report_tls_error(t: sys::esp_transport_handle_t, tls: *mut sys::esp_tls_t) {
    let mut tls_error: sys::esp_tls_error_handle_t = ptr::null_mut();
    let transport_error = sys::esp_transport_get_error_handle(t);
    if sys::esp_tls_get_error_handle(tls, &mut tls_error) == sys::ESP_OK
        && !tls_error.is_null()
        && !transport_error.is_null()
    {
        *transport_error = *tls_error;
    }
}

unsafe extern "C" fn read(
    t: sys::esp_transport_handle_t,
    buffer: *mut c_char,
    len: c_int,
    timeout_ms: c_int,
) -> c_int {
    let Some(ctx) = context(t) else { return -1 };

    match ctx.poll_read(timeout_ms) {
        p if p < 0 => return sys::esp_tcp_transport_err_t_ERR_TCP_TRANSPORT_CONNECTION_FAILED,
        0 => return sys::esp_tcp_transport_err_t_ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT,
        _ => {}
    }

    let n = sys::esp_tls_conn_read(ctx.tls, buffer.cast(), len as usize) as c_int;

    // esp-tls takes a TLS 1.3 ticket in inside the read, and holds it for
    // `esp_tls_get_client_session`. The server sends it straight after the
    // handshake, so it is here by the first read or two.
    #[cfg(all(esp_idf_esp_tls_client_session_tickets, esp_idf_mbedtls_ssl_proto_tls1_3))]
    if let Some(handshake) = ctx.ticket_due {
        if let Some(ticket) = save_session(ctx.tls) {
            ctx.settings.session.store(ticket, handshake);
            ctx.ticket_due = None;
        }
    }

    if n == sys::MBEDTLS_ERR_SSL_WANT_READ || n == sys::MBEDTLS_ERR_SSL_TIMEOUT {
        sys::esp_tcp_transport_err_t_ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT
    } else if n < 0 {
        report_tls_error(t, ctx.tls);
        n
    } else if n == 0 {
        // Readable, and nothing to read: the server closed the connection.
        sys::esp_tcp_transport_err_t_ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN
    } else {
        n
    }
}

unsafe extern "C" fn write(
    t: sys::esp_transport_handle_t,
    buffer: *const c_char,
    len: c_int,
    timeout_ms: c_int,
) -> c_int {
    let Some(ctx) = context(t) else { return -1 };

    let ready = ctx.poll_write(timeout_ms);
    if ready <= 0 {
        return ready;
    }

    let n = sys::esp_tls_conn_write(ctx.tls, buffer.cast(), len as usize) as c_int;
    if n < 0 {
        report_tls_error(t, ctx.tls);
    }
    n
}

unsafe extern "C" fn poll_read(t: sys::esp_transport_handle_t, timeout_ms: c_int) -> c_int {
    context(t).map_or(-1, |ctx| ctx.poll_read(timeout_ms))
}

unsafe extern "C" fn poll_write(t: sys::esp_transport_handle_t, timeout_ms: c_int) -> c_int {
    context(t).map_or(-1, |ctx| ctx.poll_write(timeout_ms))
}

// The polls take the context rather than the handle so that `read` and
// `write`, which already hold it, don't borrow it a second time.
impl Context {
    fn poll_read(&self, timeout_ms: c_int) -> c_int {
        if self.tls.is_null() {
            return -1;
        }

        // mbedTLS may already hold decrypted bytes the socket has no record of.
        let buffered = unsafe { sys::esp_tls_get_bytes_avail(self.tls) };
        if buffered > 0 {
            return buffered as c_int;
        }

        unsafe { wait(self.sockfd, Direction::Read, timeout_ms, &self.stopping) }
    }

    fn poll_write(&self, timeout_ms: c_int) -> c_int {
        if self.tls.is_null() {
            return -1;
        }

        unsafe { wait(self.sockfd, Direction::Write, timeout_ms, &self.stopping) }
    }
}

unsafe extern "C" fn close(t: sys::esp_transport_handle_t) -> c_int {
    if let Some(ctx) = context(t) {
        ctx.close();
    }
    0
}

unsafe extern "C" fn destroy(t: sys::esp_transport_handle_t) -> c_int {
    let context = sys::esp_transport_get_context_data(t) as *mut Context;
    if !context.is_null() {
        let mut context = Box::from_raw(context);
        context.close();
        sys::esp_transport_set_context_data(t, ptr::null_mut());
    }
    0
}

/// Cuts a transport's waits short, from the thread that owns the client.
///
/// The websocket client stops its task by clearing a flag the task reads
/// between polls, and its idle poll waits a second for the socket. [`stop`]
/// ends that wait early, so a client being destroyed stops in a tenth of a
/// second rather than up to a whole one with the modem on.
///
/// [`stop`]: Stopper::stop
pub(crate) struct Stopper(Arc<AtomicBool>);

impl Stopper {
    pub(crate) fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// How often a wait looks up to see whether it should stop.
const STOP_CHECK: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
enum Direction {
    Read,
    Write,
}

/// `select` on one socket: >0 ready, 0 timed out, -1 failed. A negative
/// timeout waits forever, as the transport API defines it.
///
/// In slices of [`STOP_CHECK`], so that [`stop`] is seen within one. A wait
/// only ends early when asked to stop; otherwise it runs its full timeout.
unsafe fn wait(fd: c_int, direction: Direction, timeout_ms: c_int, stopping: &AtomicBool) -> c_int {
    let deadline =
        u64::try_from(timeout_ms).ok().map(|ms| Instant::now() + Duration::from_millis(ms));

    loop {
        let slice = match deadline {
            Some(deadline) => deadline.saturating_duration_since(Instant::now()).min(STOP_CHECK),
            None => STOP_CHECK,
        };

        let n = select_once(fd, direction, slice);
        if n != 0 || stopping.load(Ordering::Relaxed) {
            return n;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return 0;
        }
    }
}

unsafe fn select_once(fd: c_int, direction: Direction, timeout: Duration) -> c_int {
    let mut ready: sys::fd_set = core::mem::zeroed();
    let mut failed: sys::fd_set = core::mem::zeroed();
    if !add(&mut ready, fd) || !add(&mut failed, fd) {
        return -1;
    }

    let mut timeout = sys::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: timeout.subsec_micros() as _,
    };

    let (reads, writes) = match direction {
        Direction::Read => (&mut ready as *mut _, ptr::null_mut()),
        Direction::Write => (ptr::null_mut(), &mut ready as *mut _),
    };

    let n = sys::select(fd + 1, reads, writes, &mut failed, &mut timeout);
    if n > 0 && contains(&failed, fd) {
        return -1;
    }
    n
}

// FD_SET and FD_ISSET are macros, so bindgen has no functions for them. lwIP
// numbers its sockets from FD_SETSIZE minus CONFIG_LWIP_MAX_SOCKETS, which is
// always inside the set; anything else is refused rather than written past it.
fn add(set: &mut sys::fd_set, fd: c_int) -> bool {
    let bits = 8 * core::mem::size_of_val(&set.__fds_bits[0]);
    let Ok(fd) = usize::try_from(fd) else { return false };
    match set.__fds_bits.get_mut(fd / bits) {
        Some(word) => {
            *word |= 1 << (fd % bits);
            true
        }
        None => false,
    }
}

fn contains(set: &sys::fd_set, fd: c_int) -> bool {
    let bits = 8 * core::mem::size_of_val(&set.__fds_bits[0]);
    let Ok(fd) = usize::try_from(fd) else { return false };
    set.__fds_bits
        .get(fd / bits)
        .is_some_and(|word| word & (1 << (fd % bits)) != 0)
}

/// A session read back from bytes, in the form esp-tls offers.
#[cfg(esp_idf_esp_tls_client_session_tickets)]
struct LoadedSession(Box<sys::esp_tls_client_session_t>);

#[cfg(esp_idf_esp_tls_client_session_tickets)]
impl LoadedSession {
    fn load(bytes: &[u8]) -> Option<Self> {
        let mut session: Box<sys::esp_tls_client_session_t> =
            Box::new(unsafe { core::mem::zeroed() });
        unsafe { sys::mbedtls_ssl_session_init(&mut session.saved_session) };
        let mut loaded = Self(session);

        // Refused when another mbedTLS version or configuration wrote it, as
        // after a firmware update; the handshake is then a full one.
        let ret = unsafe {
            sys::mbedtls_ssl_session_load(&mut loaded.0.saved_session, bytes.as_ptr(), bytes.len())
        };
        if ret != 0 {
            return None;
        }

        #[cfg(all(esp_idf_mbedtls_ssl_proto_tls1_3, esp_idf_mbedtls_have_time))]
        redate_ticket(&mut loaded.0.saved_session, TicketClock::Mbedtls);

        Some(loaded)
    }

    fn as_mut_ptr(&mut self) -> *mut sys::esp_tls_client_session_t {
        &mut *self.0
    }
}

#[cfg(esp_idf_esp_tls_client_session_tickets)]
impl Drop for LoadedSession {
    fn drop(&mut self) {
        unsafe { sys::mbedtls_ssl_session_free(&mut self.0.saved_session) };
    }
}

/// The connection's session, as bytes.
///
/// TLS 1.2 lets mbedTLS export a session once per connection, so for 1.2 this
/// is called once, straight after the handshake. A TLS 1.3 session is the
/// ticket the server sends after the handshake; until a read has taken one
/// in, esp-tls has nothing to give and this returns `None`.
#[cfg(esp_idf_esp_tls_client_session_tickets)]
unsafe fn save_session(tls: *mut sys::esp_tls_t) -> Option<Vec<u8>> {
    let session = sys::esp_tls_get_client_session(tls);
    if session.is_null() {
        return None;
    }

    #[cfg(all(esp_idf_mbedtls_ssl_proto_tls1_3, esp_idf_mbedtls_have_time))]
    redate_ticket(&mut (*session).saved_session, TicketClock::Wall);

    let mut len = 0usize;
    sys::mbedtls_ssl_session_save(&(*session).saved_session, ptr::null_mut(), 0, &mut len);

    let mut bytes = vec![0u8; len];
    let ret = sys::mbedtls_ssl_session_save(
        &(*session).saved_session,
        bytes.as_mut_ptr(),
        bytes.len(),
        &mut len,
    );
    sys::esp_tls_free_client_session(session);

    (ret == 0).then(|| {
        bytes.truncate(len);
        bytes
    })
}

/// Which clock a TLS 1.3 ticket's date is on: mbedTLS's, which restarts at
/// every boot, while the session is in use; the wall clock's, which goes on
/// through deep sleep, while it is saved. See `TlsSession`'s module docs.
#[cfg(all(
    esp_idf_esp_tls_client_session_tickets,
    esp_idf_mbedtls_ssl_proto_tls1_3,
    esp_idf_mbedtls_have_time
))]
#[derive(Clone, Copy)]
enum TicketClock {
    Mbedtls,
    Wall,
}

/// Move a TLS 1.3 session's ticket date onto `to`, keeping its age. Anything
/// else -- a TLS 1.2 session, one with no ticket -- is left as it is.
#[cfg(all(
    esp_idf_esp_tls_client_session_tickets,
    esp_idf_mbedtls_ssl_proto_tls1_3,
    esp_idf_mbedtls_have_time
))]
fn redate_ticket(session: &mut sys::mbedtls_ssl_session, to: TicketClock) {
    if session.private_tls_version != sys::mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_3
        || session.private_ticket.is_null()
    {
        return;
    }

    let mbedtls_now = unsafe { sys::mbedtls_ms_time() };
    let wall_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as i64);
    let (from_now, to_now) = match to {
        TicketClock::Wall => (mbedtls_now, wall_now),
        TicketClock::Mbedtls => (wall_now, mbedtls_now),
    };

    session.private_ticket_reception_time =
        crate::tls_session::rebase(session.private_ticket_reception_time, from_now, to_now);
}

/// The protocol the handshake settled on, as mbedTLS names it.
unsafe fn protocol(tls: *mut sys::esp_tls_t) -> Option<String> {
    let ssl = sys::esp_tls_get_ssl_context(tls) as *const sys::mbedtls_ssl_context;
    if ssl.is_null() {
        return None;
    }
    let name = sys::mbedtls_ssl_get_version(ssl);
    (!name.is_null()).then(|| CStr::from_ptr(name).to_string_lossy().into_owned())
}

/// Whether the connection settled on TLS 1.3.
#[cfg(all(esp_idf_esp_tls_client_session_tickets, esp_idf_mbedtls_ssl_proto_tls1_3))]
unsafe fn is_tls13(tls: *mut sys::esp_tls_t) -> bool {
    let ssl = sys::esp_tls_get_ssl_context(tls) as *const sys::mbedtls_ssl_context;
    !ssl.is_null() && CStr::from_ptr(sys::mbedtls_ssl_get_version(ssl)).to_bytes() == b"TLSv1.3"
}

/// Whether a TLS 1.3 handshake resumed the offered session.
///
/// The TLS 1.2 test -- the session's bytes unchanged -- can't work here: each
/// connection gets a new ticket either way. But a saved 1.3 session carries no
/// certificate (mbedTLS doesn't write one), and a resumed handshake sends
/// none, so afterwards mbedTLS has no peer certificate; after a full handshake
/// it has the server's. TLS 1.3 needs `CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE`
/// in ESP-IDF, so a full handshake always keeps it.
#[cfg(all(esp_idf_esp_tls_client_session_tickets, esp_idf_mbedtls_ssl_proto_tls1_3))]
unsafe fn tls13_handshake(tls: *mut sys::esp_tls_t, offered: bool) -> Handshake {
    let ssl = sys::esp_tls_get_ssl_context(tls) as *const sys::mbedtls_ssl_context;
    if offered && !ssl.is_null() && sys::mbedtls_ssl_get_peer_cert(ssl).is_null() {
        Handshake::Resumed
    } else {
        Handshake::Full
    }
}
