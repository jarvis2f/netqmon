#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
export COPYFILE_DISABLE=1

BINARY_PATH="${1:-}"
ARCH="${2:-x86_64}"
VERSION="${3:-0.1.0-1}"
OUTPUT_DIR="${4:-${ROOT_DIR}/dist}"
LUCI_VERSION="${LUCI_VERSION:-${VERSION}}"

if [[ -z "${BINARY_PATH}" || ! -f "${BINARY_PATH}" ]]; then
    echo "Usage: $0 <binary_path> [architecture] [version] [output_dir]" >&2
    echo "Error: binary_path must be a valid file" >&2
    exit 1
fi

BINARY_PATH="$(cd "$(dirname "${BINARY_PATH}")" && pwd)/$(basename "${BINARY_PATH}")"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

DATA_DIR="${TMP_DIR}/data"
CONTROL_DIR="${TMP_DIR}/control"
mkdir -p "${DATA_DIR}/usr/bin" "${DATA_DIR}/usr/share/netqmon" "${DATA_DIR}/etc/config" "${DATA_DIR}/etc/init.d" "${CONTROL_DIR}" "${OUTPUT_DIR}"

# 1. Populate data payload
cp "${BINARY_PATH}" "${DATA_DIR}/usr/bin/netqmon-agent"
chmod 0755 "${DATA_DIR}/usr/bin/netqmon-agent"

cp "${SCRIPT_DIR}/files/etc/config/netqmon" "${DATA_DIR}/etc/config/netqmon"
chmod 0644 "${DATA_DIR}/etc/config/netqmon"

cp "${SCRIPT_DIR}/files/etc/init.d/netqmon" "${DATA_DIR}/etc/init.d/netqmon"
chmod 0755 "${DATA_DIR}/etc/init.d/netqmon"

cp "${ROOT_DIR}/scripts/benchmark/openwrt-sfo-compatibility.sh" "${DATA_DIR}/usr/share/netqmon/openwrt-sfo-compatibility.sh"
chmod 0755 "${DATA_DIR}/usr/share/netqmon/openwrt-sfo-compatibility.sh"

# 2. Populate control files
cat << EOF > "${CONTROL_DIR}/control"
Package: netqmon-agent
Version: ${VERSION}
Depends: kmod-sched-core, kmod-sched-bpf
Section: net
Architecture: ${ARCH}
Maintainer: netqmon Authors
Description: NetQMon eBPF network telemetry agent for OpenWrt
EOF

cat << EOF > "${CONTROL_DIR}/conffiles"
/etc/config/netqmon
EOF

cat << 'EOF' > "${CONTROL_DIR}/postinst"
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] || {
    /etc/init.d/netqmon enable
    /etc/init.d/netqmon start
}
exit 0
EOF
chmod 0755 "${CONTROL_DIR}/postinst"

cat << 'EOF' > "${CONTROL_DIR}/prerm"
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] || {
    /etc/init.d/netqmon stop 2>/dev/null || true
    /etc/init.d/netqmon disable 2>/dev/null || true
}
exit 0
EOF
chmod 0755 "${CONTROL_DIR}/prerm"

# 3. Create sub-archives
(cd "${DATA_DIR}" && tar --format ustar -czf "${TMP_DIR}/data.tar.gz" .)
(cd "${CONTROL_DIR}" && tar --format ustar -czf "${TMP_DIR}/control.tar.gz" .)
printf "2.0\n" > "${TMP_DIR}/debian-binary"

# 4. Create agent package
PACKAGE_NAME="netqmon-agent_${VERSION}_${ARCH}.ipk"
PACKAGE_FILE="${OUTPUT_DIR}/${PACKAGE_NAME}"

(cd "${TMP_DIR}" && tar --format ustar -czf "${PACKAGE_FILE}" ./debian-binary ./control.tar.gz ./data.tar.gz)

echo "Successfully built OpenWrt package: ${PACKAGE_FILE}"
tar -ztvf "${PACKAGE_FILE}"

# 5. Create LuCI package
LUCI_TMP_DIR="${TMP_DIR}/luci"
LUCI_DATA_DIR="${LUCI_TMP_DIR}/data"
LUCI_CONTROL_DIR="${LUCI_TMP_DIR}/control"
mkdir -p "${LUCI_DATA_DIR}" "${LUCI_CONTROL_DIR}"
cp -R "${SCRIPT_DIR}/luci-app-netqmon/root/." "${LUCI_DATA_DIR}/"
chmod 0755 "${LUCI_DATA_DIR}/usr/libexec/rpcd/netqmon"
chmod 0755 "${LUCI_DATA_DIR}/usr/libexec/netqmon/update-agent"

cat << EOF > "${LUCI_CONTROL_DIR}/control"
Package: luci-app-netqmon
Version: ${LUCI_VERSION}
Depends: netqmon-agent, rpcd, jsonfilter
Section: luci
Architecture: all
Maintainer: netqmon Authors
Description: LuCI management interface for NetQMon Agent
EOF

(cd "${LUCI_DATA_DIR}" && tar --format ustar -czf "${LUCI_TMP_DIR}/data.tar.gz" .)
(cd "${LUCI_CONTROL_DIR}" && tar --format ustar -czf "${LUCI_TMP_DIR}/control.tar.gz" .)
printf "2.0\n" > "${LUCI_TMP_DIR}/debian-binary"

LUCI_PACKAGE_NAME="luci-app-netqmon_${LUCI_VERSION}_all.ipk"
LUCI_PACKAGE_FILE="${OUTPUT_DIR}/${LUCI_PACKAGE_NAME}"

(cd "${LUCI_TMP_DIR}" && tar --format ustar -czf "${LUCI_PACKAGE_FILE}" ./debian-binary ./control.tar.gz ./data.tar.gz)

echo "Successfully built OpenWrt package: ${LUCI_PACKAGE_FILE}"
tar -ztvf "${LUCI_PACKAGE_FILE}"
