#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UCI_CONFIG="${ROOT_DIR}/packaging/openwrt/files/etc/config/netqmon"
INIT_SCRIPT="${ROOT_DIR}/packaging/openwrt/files/etc/init.d/netqmon"
LUCI_DIR="${ROOT_DIR}/packaging/openwrt/luci-app-netqmon"
ADVANCED_JS="${LUCI_DIR}/root/www/luci-static/resources/view/netqmon/advanced.js"
GENERAL_JS="${LUCI_DIR}/root/www/luci-static/resources/view/netqmon/general.js"
STATUS_JS="${LUCI_DIR}/root/www/luci-static/resources/view/netqmon/status.js"
UPDATE_JS="${LUCI_DIR}/root/www/luci-static/resources/view/netqmon/update.js"
RPC_PLUGIN="${LUCI_DIR}/root/usr/libexec/rpcd/netqmon"
UPDATE_HELPER="${LUCI_DIR}/root/usr/libexec/netqmon/update-agent"
MENU_JSON="${LUCI_DIR}/root/usr/share/luci/menu.d/luci-app-netqmon.json"
ACL_JSON="${LUCI_DIR}/root/usr/share/rpcd/acl.d/luci-app-netqmon.json"
BUILD_SCRIPT="${ROOT_DIR}/packaging/openwrt/build-ipk.sh"
INSTALLER="${ROOT_DIR}/scripts/install-agent.sh"
OPENWRT_WORKFLOW="${ROOT_DIR}/.github/workflows/openwrt.yml"
MANIFEST_GENERATOR="${ROOT_DIR}/scripts/release/generate_openwrt_manifest.py"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_file() {
    [[ -f "$1" ]] || fail "missing file $1"
}

assert_contains() {
    local file="$1"
    local pattern="$2"
    grep -Eq "$pattern" "$file" || fail "$file does not contain pattern: $pattern"
}

uci_options() {
    awk '$1 == "option" { print $2 }' "$UCI_CONFIG" | sort
}

assert_luci_option() {
    local option="$1"
    grep -R "['\"]${option}['\"]" "$GENERAL_JS" "$ADVANCED_JS" >/dev/null ||
        fail "LuCI forms do not expose UCI option ${option}"
}

assert_env_bridge() {
    local option="$1"
    local env_name="$2"
    assert_contains "$INIT_SCRIPT" "config_get(_bool)? [^ ]+ main ${option}"
    assert_contains "$INIT_SCRIPT" "${env_name}="
}

assert_file "$MENU_JSON"
assert_file "$ACL_JSON"
assert_file "$GENERAL_JS"
assert_file "$ADVANCED_JS"
assert_file "$STATUS_JS"
assert_file "$UPDATE_JS"
assert_file "$RPC_PLUGIN"
assert_file "$UPDATE_HELPER"
assert_file "$INSTALLER"
assert_file "$OPENWRT_WORKFLOW"
assert_file "$MANIFEST_GENERATOR"

for page in status general advanced update; do
    assert_contains "$MENU_JSON" "netqmon/${page}"
done

for method in status doctor service update_status update_check update_apply; do
    assert_contains "$ACL_JSON" "\"${method}\""
    assert_contains "$RPC_PLUGIN" "${method}"
done

for option in $(uci_options); do
    case "$option" in
        update_channel) assert_luci_option "$option" ;;
        *) assert_luci_option "$option" ;;
    esac
done

assert_env_bridge interface NETQMON_INTERFACE
assert_contains "$INIT_SCRIPT" "config_list_foreach main interfaces"
assert_contains "$INIT_SCRIPT" "NETQMON_INTERFACES="
assert_env_bridge controller_url NETQMON_CONTROLLER_URL
assert_env_bridge token NETQMON_TOKEN
assert_env_bridge poll_interval_ms NETQMON_POLL_INTERVAL_MS
assert_env_bridge batch_interval_ms NETQMON_BATCH_INTERVAL_MS
assert_env_bridge max_flows NETQMON_MAX_FLOWS
assert_env_bridge retry_buffer_seconds NETQMON_RETRY_BUFFER_SECONDS
assert_env_bridge telemetry_retry_buffer_bytes NETQMON_TELEMETRY_RETRY_BUFFER_BYTES
assert_env_bridge tcp_idle_timeout_seconds NETQMON_TCP_IDLE_TIMEOUT_SECONDS
assert_env_bridge udp_idle_timeout_seconds NETQMON_UDP_IDLE_TIMEOUT_SECONDS
assert_env_bridge sample_enabled NETQMON_SAMPLE_ENABLED
assert_env_bridge sample_max_packets_per_direction NETQMON_SAMPLE_MAX_PACKETS_PER_DIRECTION
assert_env_bridge sample_max_bytes_per_packet NETQMON_SAMPLE_MAX_BYTES_PER_PACKET
assert_env_bridge sample_max_bytes_per_flow NETQMON_SAMPLE_MAX_BYTES_PER_FLOW
assert_env_bridge interface_counter_sanity_enabled NETQMON_INTERFACE_COUNTER_SANITY_ENABLED
assert_env_bridge interface_counter_min_bytes NETQMON_INTERFACE_COUNTER_MIN_BYTES
assert_env_bridge interface_counter_max_unaccounted_ratio NETQMON_INTERFACE_COUNTER_MAX_UNACCOUNTED_RATIO

assert_contains "$RPC_PLUGIN" "netqmon-agent"
assert_contains "$RPC_PLUGIN" "doctor"
assert_contains "$GENERAL_JS" 'form.DynamicList, "interfaces"'
assert_contains "$GENERAL_JS" "callNetworkDevices"
assert_contains "$GENERAL_JS" 'uci.get.*"interface"'
assert_contains "$GENERAL_JS" 'uci.set.*"interfaces".*interfaces'
assert_contains "$GENERAL_JS" 'uci.set.*"interface".*interfaces\[0\]'
assert_contains "$GENERAL_JS" "interfaces.length < 1 \|\| interfaces.length > 32"
assert_contains "$GENERAL_JS" "o.isValid.*function"
assert_contains "$RPC_PLUGIN" "config_list_foreach main interfaces"
assert_contains "$RPC_PLUGIN" '"interfaces":\['
assert_contains "$STATUS_JS" "formatInterfaces"
assert_contains "$ACL_JSON" '"luci-rpc"'
assert_contains "$UPDATE_HELPER" "validate_package_url"
assert_contains "$UPDATE_HELPER" "sha256sum"
assert_contains "$UPDATE_HELPER" "opkg install"
assert_contains "$UPDATE_HELPER" "github.com/jarvis2f/netqmon/releases/download/.*/netqmon-agent_.*\\.ipk"
assert_contains "$UPDATE_HELPER" "unsupported update channel"
assert_contains "$UPDATE_HELPER" "api.github.com/repos/jarvis2f/netqmon/releases"
assert_contains "$UPDATE_HELPER" "prerelease"
assert_contains "$UPDATE_HELPER" "no newer package is available"
assert_contains "$OPENWRT_WORKFLOW" "generate_openwrt_manifest.py"
assert_contains "$OPENWRT_WORKFLOW" "publish-release-assets"
assert_contains "$MANIFEST_GENERATOR" "openwrt_arch"
assert_contains "$MANIFEST_GENERATOR" "sha256"
assert_contains "$BUILD_SCRIPT" "luci-app-netqmon_"
assert_contains "$BUILD_SCRIPT" "Package: luci-app-netqmon"
assert_contains "$INSTALLER" "openwrt-agent-manifest\\.json"
assert_contains "$INSTALLER" "luci-app-netqmon"
assert_contains "$INSTALLER" 'opkg install "\$agent_pkg" "\$luci_pkg"'

echo "OpenWrt LuCI packaging checks passed."
