#!/bin/sh
set -eu

echo "=== NetQMon OpenWrt Agent Standalone Installer ==="

# Check root permissions
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this installer must be run as root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NETQMON_DEFAULT_RELEASE_TAG="${NETQMON_DEFAULT_RELEASE_TAG:-}"

# 1. Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="aarch64"
        ;;
    *)
        echo "Warning: unverified architecture: $ARCH (assuming $ARCH)"
        TARGET_ARCH="$ARCH"
        ;;
esac
echo "Detected architecture: ${TARGET_ARCH}"

# 2. Check kernel module dependencies
check_and_install_deps() {
    local missing=""
    if [ -f /proc/modules ]; then
        grep -q "cls_bpf" /proc/modules || missing="$missing kmod-sched-bpf"
        grep -Eq "sch_ingress|sch_clsact" /proc/modules || missing="$missing kmod-sched-core"
    fi

    if [ -n "$missing" ]; then
        echo "Missing required kernel modules:$missing"
        if command -v opkg >/dev/null 2>&1; then
            echo "Attempting to install via opkg..."
            opkg update || true
            # shellcheck disable=SC2086
            opkg install $missing || true
        elif command -v apk >/dev/null 2>&1; then
            echo "Attempting to install via apk..."
            apk update || true
            # shellcheck disable=SC2086
            apk add $missing || true
        else
            echo "Please manually install the following packages:$missing"
        fi
    else
        echo "Kernel module dependencies satisfied."
    fi
}
check_and_install_deps

# 3. Prefer OpenWrt IPK installation when opkg is available. This installs both
# the agent package and the LuCI management app from local packages or GitHub
# release assets, then exits before the standalone binary fallback.
download_file() {
    local url="$1"
    local output="$2"
    if command -v wget >/dev/null 2>&1; then
        if [ -n "${NETQMON_GITHUB_TOKEN:-}" ]; then
            wget -q --header="Authorization: Bearer ${NETQMON_GITHUB_TOKEN}" -O "$output" "$url"
        else
            wget -q -O "$output" "$url"
        fi
    elif command -v curl >/dev/null 2>&1; then
        if [ -n "${NETQMON_GITHUB_TOKEN:-}" ]; then
            curl -fsSL -H "Authorization: Bearer ${NETQMON_GITHUB_TOKEN}" "$url" -o "$output"
        else
            curl -fsSL "$url" -o "$output"
        fi
    else
        return 1
    fi
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

first_existing_file() {
    local pattern file
    for pattern in "$@"; do
        for file in $pattern; do
            [ -f "$file" ] || continue
            printf '%s' "$file"
            return 0
        done
    done
    return 1
}

release_download_base_url() {
    local tag="${NETQMON_RELEASE_TAG:-$NETQMON_DEFAULT_RELEASE_TAG}"
    if [ -n "$tag" ]; then
        printf 'https://github.com/jarvis2f/netqmon/releases/download/%s' "$tag"
    else
        printf 'https://github.com/jarvis2f/netqmon/releases/latest/download'
    fi
}

install_openwrt_ipks() {
    [ "${NETQMON_INSTALL_IPK:-1}" = "1" ] || return 1
    command -v opkg >/dev/null 2>&1 || return 1

    local tmp_dir base_url manifest agent_pkg luci_pkg agent_url luci_url agent_sha luci_sha actual
    tmp_dir="${TMPDIR:-/tmp}/netqmon-install"
    base_url="${NETQMON_RELEASE_BASE_URL:-$(release_download_base_url)}"
    mkdir -p "$tmp_dir"

    agent_pkg="$(first_existing_file \
        "${SCRIPT_DIR}/netqmon-agent_"*"_${TARGET_ARCH}.ipk" \
        "${SCRIPT_DIR}/netqmon-agent_${TARGET_ARCH}.ipk" \
        "${SCRIPT_DIR}/dist/netqmon-agent_"*"_${TARGET_ARCH}.ipk" \
        "${SCRIPT_DIR}/dist/netqmon-agent_${TARGET_ARCH}.ipk" 2>/dev/null || true)"
    luci_pkg="$(first_existing_file \
        "${SCRIPT_DIR}/luci-app-netqmon_"*"_all.ipk" \
        "${SCRIPT_DIR}/luci-app-netqmon_all.ipk" \
        "${SCRIPT_DIR}/dist/luci-app-netqmon_"*"_all.ipk" \
        "${SCRIPT_DIR}/dist/luci-app-netqmon_all.ipk" 2>/dev/null || true)"

    if [ -z "$agent_pkg" ] || [ -z "$luci_pkg" ]; then
        manifest="$tmp_dir/openwrt-agent-manifest.json"
        echo "Downloading release manifest from ${base_url}/openwrt-agent-manifest.json..."
        download_file "${base_url}/openwrt-agent-manifest.json" "$manifest" || return 1

        if command -v jsonfilter >/dev/null 2>&1; then
            agent_url="$(jsonfilter -i "$manifest" -e "@.channels.stable.packages[@.name='netqmon-agent'][@.openwrt_arch='${TARGET_ARCH}'].url" 2>/dev/null | head -n 1)"
            agent_sha="$(jsonfilter -i "$manifest" -e "@.channels.stable.packages[@.name='netqmon-agent'][@.openwrt_arch='${TARGET_ARCH}'].sha256" 2>/dev/null | head -n 1)"
            luci_url="$(jsonfilter -i "$manifest" -e "@.channels.stable.packages[@.name='luci-app-netqmon'][@.openwrt_arch='all'].url" 2>/dev/null | head -n 1)"
            luci_sha="$(jsonfilter -i "$manifest" -e "@.channels.stable.packages[@.name='luci-app-netqmon'][@.openwrt_arch='all'].sha256" 2>/dev/null | head -n 1)"
        fi

        agent_url="${agent_url:-${base_url}/netqmon-agent_${TARGET_ARCH}.ipk}"
        luci_url="${luci_url:-${base_url}/luci-app-netqmon_all.ipk}"
        agent_pkg="$tmp_dir/netqmon-agent_${TARGET_ARCH}.ipk"
        luci_pkg="$tmp_dir/luci-app-netqmon_all.ipk"

        echo "Downloading netqmon-agent package..."
        download_file "$agent_url" "$agent_pkg" || return 1
        echo "Downloading luci-app-netqmon package..."
        download_file "$luci_url" "$luci_pkg" || return 1

        if [ -n "${agent_sha:-}" ]; then
            actual="$(sha256_file "$agent_pkg")"
            [ "$actual" = "$agent_sha" ] || {
                echo "Error: netqmon-agent package checksum mismatch." >&2
                return 1
            }
        fi
        if [ -n "${luci_sha:-}" ]; then
            actual="$(sha256_file "$luci_pkg")"
            [ "$actual" = "$luci_sha" ] || {
                echo "Error: luci-app-netqmon package checksum mismatch." >&2
                return 1
            }
        fi
    fi

    echo "Installing OpenWrt packages..."
    opkg install "$agent_pkg" "$luci_pkg"

    if [ -x /etc/init.d/rpcd ]; then
        /etc/init.d/rpcd restart || true
    fi
    if [ -x /etc/init.d/uhttpd ]; then
        /etc/init.d/uhttpd reload 2>/dev/null || /etc/init.d/uhttpd restart || true
    fi
    if [ -x /etc/init.d/netqmon ]; then
        /etc/init.d/netqmon enable
        /etc/init.d/netqmon restart
    fi

    echo "=== NetQMon Agent and LuCI app successfully installed ==="
    echo "LuCI path: Services -> NetQMon"
    echo "Check status with: ubus call netqmon status"
    return 0
}

if install_openwrt_ipks; then
    exit 0
fi

if command -v opkg >/dev/null 2>&1 && [ "${NETQMON_INSTALL_IPK:-1}" = "1" ]; then
    echo "Error: OpenWrt package installation failed." >&2
    echo "Set NETQMON_INSTALL_IPK=0 to use the standalone binary fallback." >&2
    exit 1
fi

# 4. Locate binary
BINARY_SOURCE=""
if [ -f "${SCRIPT_DIR}/netqmon-agent" ]; then
    BINARY_SOURCE="${SCRIPT_DIR}/netqmon-agent"
elif [ -f "${SCRIPT_DIR}/netqmon-agent_${TARGET_ARCH}" ]; then
    BINARY_SOURCE="${SCRIPT_DIR}/netqmon-agent_${TARGET_ARCH}"
elif [ -f "${SCRIPT_DIR}/bin/netqmon-agent" ]; then
    BINARY_SOURCE="${SCRIPT_DIR}/bin/netqmon-agent"
elif [ -f "/usr/bin/netqmon-agent" ]; then
    echo "netqmon-agent binary already present in /usr/bin."
    BINARY_SOURCE="/usr/bin/netqmon-agent"
fi

if [ -n "$BINARY_SOURCE" ] && [ "$BINARY_SOURCE" != "/usr/bin/netqmon-agent" ]; then
    echo "Installing binary to /usr/bin/netqmon-agent..."
    cp "$BINARY_SOURCE" /usr/bin/netqmon-agent
    chmod 0755 /usr/bin/netqmon-agent
fi

if [ ! -x /usr/bin/netqmon-agent ]; then
    echo "Error: /usr/bin/netqmon-agent not found or not executable." >&2
    exit 1
fi

# 5. Install UCI configuration (preserve existing)
mkdir -p /etc/config
if [ -f /etc/config/netqmon ]; then
    echo "Preserving existing configuration at /etc/config/netqmon"
else
    echo "Installing default configuration to /etc/config/netqmon..."
    if [ -f "${SCRIPT_DIR}/netqmon.config" ]; then
        cp "${SCRIPT_DIR}/netqmon.config" /etc/config/netqmon
    elif [ -f "${SCRIPT_DIR}/../packaging/openwrt/files/etc/config/netqmon" ]; then
        cp "${SCRIPT_DIR}/../packaging/openwrt/files/etc/config/netqmon" /etc/config/netqmon
    else
        cat << 'EOF' > /etc/config/netqmon
config agent 'main'
    option enabled '1'
    option interface 'br-lan'
    list interfaces 'br-lan'
    option controller_url 'http://127.0.0.1:8090'
    option token ''
    option poll_interval_ms '1000'
    option batch_interval_ms '1000'
    option max_flows '65536'
    option retry_buffer_seconds '60'
    option telemetry_retry_buffer_bytes '8388608'
    option tcp_idle_timeout_seconds '120'
    option udp_idle_timeout_seconds '30'
EOF
    fi
    chmod 0644 /etc/config/netqmon
fi

# 6. Install procd init script
mkdir -p /etc/init.d
echo "Installing init script to /etc/init.d/netqmon..."
if [ -f "${SCRIPT_DIR}/netqmon.init" ]; then
    cp "${SCRIPT_DIR}/netqmon.init" /etc/init.d/netqmon
elif [ -f "${SCRIPT_DIR}/../packaging/openwrt/files/etc/init.d/netqmon" ]; then
    cp "${SCRIPT_DIR}/../packaging/openwrt/files/etc/init.d/netqmon" /etc/init.d/netqmon
else
    cat << 'EOF' > /etc/init.d/netqmon
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=99
STOP=10

PROG=/usr/bin/netqmon-agent

append_capture_interface() {
    [ -z "$interfaces" ] || interfaces="${interfaces},"
    interfaces="${interfaces}$1"
}

start_service() {
    config_load netqmon

    local enabled
    config_get_bool enabled main enabled 1
    [ "$enabled" -eq 1 ] || return 0

    local interface interfaces controller_url token poll_interval_ms batch_interval_ms max_flows retry_buffer_seconds telemetry_retry_buffer_bytes tcp_idle_timeout_seconds udp_idle_timeout_seconds sample_enabled sample_bool sample_max_packets_per_direction sample_max_bytes_per_packet sample_max_bytes_per_flow interface_counter_sanity_enabled interface_counter_sanity_bool interface_counter_min_bytes interface_counter_max_unaccounted_ratio
    config_get interface main interface "br-lan"
    interfaces=
    config_list_foreach main interfaces append_capture_interface
    [ -n "$interfaces" ] || interfaces="$interface"
    config_get controller_url main controller_url "http://127.0.0.1:8090"
    config_get token main token ""
    config_get poll_interval_ms main poll_interval_ms 1000
    config_get batch_interval_ms main batch_interval_ms 1000
    config_get max_flows main max_flows 65536
    config_get retry_buffer_seconds main retry_buffer_seconds 60
    config_get telemetry_retry_buffer_bytes main telemetry_retry_buffer_bytes 8388608
    config_get tcp_idle_timeout_seconds main tcp_idle_timeout_seconds 120
    config_get udp_idle_timeout_seconds main udp_idle_timeout_seconds 30
    config_get sample_enabled main sample_enabled 1
    config_get sample_max_packets_per_direction main sample_max_packets_per_direction 4
    config_get sample_max_bytes_per_packet main sample_max_bytes_per_packet 1024
    config_get sample_max_bytes_per_flow main sample_max_bytes_per_flow 4096
    config_get interface_counter_sanity_enabled main interface_counter_sanity_enabled 1
    config_get interface_counter_min_bytes main interface_counter_min_bytes 65536
    config_get interface_counter_max_unaccounted_ratio main interface_counter_max_unaccounted_ratio 4

    case "$sample_enabled" in
        1|true|TRUE|on|ON|yes|YES) sample_bool=true ;;
        0|false|FALSE|off|OFF|no|NO) sample_bool=false ;;
        *) sample_bool="$sample_enabled" ;;
    esac
    case "$interface_counter_sanity_enabled" in
        1|true|TRUE|on|ON|yes|YES) interface_counter_sanity_bool=true ;;
        0|false|FALSE|off|OFF|no|NO) interface_counter_sanity_bool=false ;;
        *) interface_counter_sanity_bool="$interface_counter_sanity_enabled" ;;
    esac

    procd_open_instance
    procd_set_param command "$PROG" run
    procd_set_param env \
        NETQMON_INTERFACE="$interface" \
        NETQMON_INTERFACES="$interfaces" \
        NETQMON_CONTROLLER_URL="$controller_url" \
        NETQMON_TOKEN="$token" \
        NETQMON_POLL_INTERVAL_MS="$poll_interval_ms" \
        NETQMON_BATCH_INTERVAL_MS="$batch_interval_ms" \
        NETQMON_MAX_FLOWS="$max_flows" \
        NETQMON_RETRY_BUFFER_SECONDS="$retry_buffer_seconds" \
        NETQMON_TELEMETRY_RETRY_BUFFER_BYTES="$telemetry_retry_buffer_bytes" \
        NETQMON_TCP_IDLE_TIMEOUT_SECONDS="$tcp_idle_timeout_seconds" \
        NETQMON_UDP_IDLE_TIMEOUT_SECONDS="$udp_idle_timeout_seconds" \
        NETQMON_SAMPLE_ENABLED="$sample_bool" \
        NETQMON_SAMPLE_MAX_PACKETS_PER_DIRECTION="$sample_max_packets_per_direction" \
        NETQMON_SAMPLE_MAX_BYTES_PER_PACKET="$sample_max_bytes_per_packet" \
        NETQMON_SAMPLE_MAX_BYTES_PER_FLOW="$sample_max_bytes_per_flow" \
        NETQMON_INTERFACE_COUNTER_SANITY_ENABLED="$interface_counter_sanity_bool" \
        NETQMON_INTERFACE_COUNTER_MIN_BYTES="$interface_counter_min_bytes" \
        NETQMON_INTERFACE_COUNTER_MAX_UNACCOUNTED_RATIO="$interface_counter_max_unaccounted_ratio"
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

service_triggers() {
    procd_add_reload_trigger "netqmon"
}
EOF
fi
chmod 0755 /etc/init.d/netqmon

# 7. Enable and start service
echo "Enabling and starting netqmon service..."
/etc/init.d/netqmon enable
/etc/init.d/netqmon restart

echo "=== NetQMon Agent successfully installed and started ==="
echo "Check status with: /etc/init.d/netqmon status"
echo "View logs with: logread -e netqmon"
