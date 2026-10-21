#!/usr/bin/env bash
#
# Write a device identity into the `certs` NVS partition and flash it.
#
# The identity half is `nh`'s job; see "A device identity" in the README.
#
# With --ca (recommended), `nh` signs a per-device certificate with your
# organization's CA, made once with `nh ca generate --upload`. Nothing is
# uploaded: NervesHub checks the certificate against the CA on the device's
# first connection, and with Just In Time Provisioning on the CA it creates the
# device then. --ca names the CA by the time its files in <data-dir>/ca/<org>/
# are named by, as in the paths `nh ca generate` prints.
#
# Without --ca, `nh` makes a self-signed certificate and uploads it for the
# device, which has to exist in NervesHub already, in the product `nh` is set
# to. NervesHub accepts an uploaded self-signed certificate once it has
# nerves-hub/nerves_hub_web#3184.
#
#   ./scripts/provision.sh --ca 2026-10-21-09-15-02 my-device-001 /dev/tty.usbmodem1101
#   ./scripts/provision.sh my-device-001 /dev/tty.usbmodem1101
#
# This script only does the ESP-specific part: turn the key and certificate into
# an NVS image and put it on the device.
#
# Requires `nh` and an ESP-IDF environment on PATH (nvs_partition_gen.py,
# esptool.py). Run ESP-IDF's export.sh first if they are not.

set -euo pipefail

USAGE="usage: provision.sh [--ca <ca-name>] <device-identifier> [serial-port]"

CA_NAME=""
if [[ "${1:-}" == "--ca" ]]; then
  CA_NAME="${2:?${USAGE}}"
  shift 2
fi

IDENTIFIER="${1:?${USAGE}}"
PORT="${2:-}"

# Must match the `certs` partition in partitions.csv.
CERTS_OFFSET="0x3E0000"
CERTS_SIZE="0x10000"

# Must match src/identity.rs — see NAMESPACE / CERTIFICATE_KEY / PRIVATE_KEY_KEY.
NAMESPACE="nerves_hub"
CERT_KEY="device.crt"
KEY_KEY="device.key"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

if [[ -n "${CA_NAME}" ]]; then
  echo "==> Generating a certificate for ${IDENTIFIER}, signed by CA ${CA_NAME}"
  nh device certificates generate "${IDENTIFIER}" --ca "${CA_NAME}"
  echo "    There is nothing to upload: NervesHub registers the certificate on the device's first connection."
else
  echo "==> Generating a self-signed certificate for ${IDENTIFIER} and uploading it"
  nh device certificates generate "${IDENTIFIER}" --self-signed --upload
fi

# `nh` writes to <data-dir>/certificates/<org>/. `data-dir` is a global flag
# rather than a persisted setting, so it is not readable via `nh config get` —
# fall back to its default, read from the same environment variables `nh` reads.
data_dir="${NERVES_HUB_DATA_DIR:-${NERVES_CLOUD_DATA_DIR:-$HOME/.nh}}"
certs_dir="${data_dir}/certificates"

if [[ ! -d "${certs_dir}" ]]; then
  echo "No certificates directory at ${certs_dir}." >&2
  echo "Set NERVES_HUB_DATA_DIR if you use a non-default --data-dir." >&2
  exit 1
fi

# Newest match wins, so re-provisioning a device picks up the new certificate
# rather than an expired one still sitting on disk.
cert_path="$(find "${certs_dir}" -type f -name "${IDENTIFIER}*" ! -name "*key*" ! -name "*.csr" -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | head -1)"
key_path="$(find "${certs_dir}" -type f -name "${IDENTIFIER}*key*" -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | head -1)"

if [[ -z "${cert_path}" || -z "${key_path}" ]]; then
  echo "Could not find a certificate and key for ${IDENTIFIER} under ${certs_dir}." >&2
  echo "Files found:" >&2
  find "${certs_dir}" -name "${IDENTIFIER}*" >&2 || true
  exit 1
fi

echo "    certificate: ${cert_path}"
echo "    key:         ${key_path}"

cp "${cert_path}" "${workdir}/${CERT_KEY}"
cp "${key_path}" "${workdir}/${KEY_KEY}"

cat > "${workdir}/nvs.csv" <<CSV
key,type,encoding,value
${NAMESPACE},namespace,,
${CERT_KEY},file,binary,${CERT_KEY}
${KEY_KEY},file,binary,${KEY_KEY}
CSV

echo "==> Building the NVS image"
( cd "${workdir}" && nvs_partition_gen.py generate nvs.csv certs.bin "${CERTS_SIZE}" )

if [[ -z "${PORT}" ]]; then
  out="./certs-${IDENTIFIER}.bin"
  cp "${workdir}/certs.bin" "${out}"
  echo "==> No serial port given; wrote ${out}"
  echo "    Flash with: esptool.py --port <port> write_flash ${CERTS_OFFSET} ${out}"
  exit 0
fi

echo "==> Flashing to ${PORT} at ${CERTS_OFFSET}"
esptool.py --port "${PORT}" write_flash "${CERTS_OFFSET}" "${workdir}/certs.bin"

echo "==> Done. ${IDENTIFIER} is provisioned."
