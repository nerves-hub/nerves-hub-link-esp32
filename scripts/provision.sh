#!/usr/bin/env bash
#
# Write a device identity into the `certs` NVS partition and flash it.
#
# The identity half is `nh`'s job — NervesHub pins the certificate's
# fingerprint, so a self-signed per-device certificate is enough and there is no
# CA to manage. This script only does the ESP-specific part: turn the key and
# certificate into an NVS image and put it on the device.
#
#   ./scripts/provision.sh my-device-001 /dev/tty.usbmodem1101
#
# Requires `nh` and an ESP-IDF environment on PATH (nvs_partition_gen.py,
# esptool.py). Run ESP-IDF's export.sh first if they are not.

set -euo pipefail

IDENTIFIER="${1:?usage: provision.sh <device-identifier> [serial-port]}"
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

echo "==> Generating and registering a certificate for ${IDENTIFIER}"
nh device certificates generate "${IDENTIFIER}" --self-signed --upload

# `nh` writes to <data-dir>/certificates/<org>/. `data-dir` is a global flag
# rather than a persisted setting, so it is not readable via `nh config get` —
# fall back to its default.
data_dir="${NERVES_HUB_DATA_DIR:-$HOME/.nerves-hub}"
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
