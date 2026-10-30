#!/bin/sh
# Run on OpenWrt with its real jsonfilter. Package downloads and installs are mocked.
set -eu

helper=${1:?pass the path to update-agent}
installer=${2:?pass the path to install-agent.sh}
work=$(mktemp -d /tmp/netqmon-update-test.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/bin" "$work/tmp"
for cmd in jsonfilter awk sed head mkdir date sha256sum cp rm ln grep cat; do
    ln -s "$(command -v "$cmd")" "$work/bin/$cmd"
done
printf 'test package\n' > "$work/package"
sha=$(sha256sum "$work/package" | awk '{print $1}')
cat > "$work/manifest" <<EOF
{"channels":{"beta":{"version":"1.1.1-beta.4","packages":[
 {"name":"luci-app-netqmon","openwrt_arch":"aarch64_cortex-a53","package_format":"apk","version":"999","url":"wrong","sha256":"wrong"},
 {"name":"netqmon-agent","openwrt_arch":"aarch64_cortex-a72","package_format":"apk","version":"999","url":"wrong","sha256":"wrong"},
 {"name":"netqmon-agent","openwrt_arch":"aarch64_cortex-a53","package_format":"ipk","version":"1.1.1-beta.4-r1","url":"https://github.com/jarvis2f/netqmon/releases/download/v1/netqmon-agent_1.ipk","sha256":"$sha"},
 {"name":"netqmon-agent","openwrt_arch":"aarch64_cortex-a53","package_format":"apk","version":"1.1.1-r1","url":"https://github.com/jarvis2f/netqmon/releases/download/v1/netqmon-agent-1.apk","sha256":"$sha"}
]}}}
EOF
cat > "$work/bin/wget" <<'EOF'
#!/bin/sh
while [ "$1" != -O ]; do shift; done
out=$2
url=$3
case "$url" in
  *manifest*) cp "$TEST_WORK/manifest" "$out" ;;
  *.apk|*.ipk) cp "$TEST_WORK/package" "$out" ;;
  *) exit 1 ;;
esac
EOF
cat > "$work/manager" <<'EOF'
#!/bin/sh
case "$1 $2" in
  'print-architecture ') printf 'arch all 1\narch aarch64_cortex-a53 10\n' ;;
  '--print-arch ') printf '%s\n' "${TEST_ARCH:-aarch64_cortex-a53}" ;;
  'list-installed netqmon-agent') printf 'netqmon-agent - 1.0-r1\n' ;;
  'info -v') printf 'netqmon-agent-1.0-r1\n' ;;
  'compare-versions '*) exit 0 ;;
  'version -t') printf '>\n' ;;
  'install '*|'add '*) printf '%s\n' "$*" >> "$TEST_WORK/install-log" ;;
  *) exit 1 ;;
esac
EOF
cat > "$work/service" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" >> "$TEST_WORK/service-log"
EOF
cat > "$work/agent" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$work/bin/wget" "$work/manager" "$work/service" "$work/agent"
sed -e "s|^SERVICE=.*|SERVICE=$work/service|" \
    -e "s|^AGENT=.*|AGENT=$work/agent|" \
    -e "s|/tmp/netqmon-opkg.log|$work/opkg.log|g" \
    -e "s|/tmp/netqmon-apk.log|$work/apk.log|g" \
    -e "s|/tmp/netqmon-doctor.log|$work/doctor.log|g" "$helper" > "$work/update-agent"
export TEST_WORK="$work" TMPDIR="$work/tmp" NETQMON_UPDATE_CHANNEL=beta
export NETQMON_UPDATE_MANIFEST_URL=https://example.invalid/manifest
export PATH="$work/bin"

assert_json() {
    actual=$(jsonfilter -s "$1" -e "@.$2")
    [ "$actual" = "$3" ] || { printf 'FAIL: %s: expected %s, got %s\n' "$2" "$3" "$actual" >&2; exit 1; }
}

for manager in opkg apk; do
    rm -f "$work/bin/opkg" "$work/bin/apk" "$work/install-log" "$work/service-log"
    ln -s "$work/manager" "$work/bin/$manager"
    result=$(/bin/sh "$work/update-agent" check)
    assert_json "$result" ok true
    assert_json "$result" latest_version 1.1.1-beta.4
    assert_json "$result" update_available true
    [ "$manager" = opkg ] && format=ipk || format=apk
    assert_json "$result" package_format "$format"
    result=$(/bin/sh "$work/update-agent" apply)
    assert_json "$result" ok true
    [ -s "$work/install-log" ] && [ -s "$work/service-log" ]
done

export TEST_ARCH=aarch64_unknown
result=$(/bin/sh "$work/update-agent" check)
assert_json "$result" ok false
assert_json "$result" latest_version 1.1.1-beta.4
assert_json "$result" error 'manifest has no package for this architecture (aarch64_unknown, apk)'
unset TEST_ARCH
printf 'corrupt package\n' > "$work/package"
rm -f "$work/install-log" "$work/service-log"
result=$(/bin/sh "$work/update-agent" apply)
assert_json "$result" ok false
assert_json "$result" error 'downloaded package checksum mismatch'
[ ! -e "$work/install-log" ] && [ ! -e "$work/service-log" ]

# Exercise the installer's actual package selection without starting system services.
printf 'test package\n' > "$work/package"
cat > "$work/manifest" <<EOF
{"channels":{"stable":{"version":"1.0.0","packages":[
 {"name":"netqmon-agent","openwrt_arch":"aarch64_cortex-a53","package_format":"ipk","url":"https://example.invalid/agent.ipk","sha256":"$sha"},
 {"name":"luci-app-netqmon","openwrt_arch":"all","package_format":"ipk","url":"https://example.invalid/luci.ipk","sha256":"$sha"},
 {"name":"netqmon-agent","openwrt_arch":"aarch64_cortex-a53","package_format":"apk","url":"https://example.invalid/agent.apk","sha256":"$sha"},
 {"name":"luci-app-netqmon","openwrt_arch":"aarch64_cortex-a53","package_format":"apk","url":"https://example.invalid/luci.apk","sha256":"$sha"}
]}}}
EOF
sed -n '/^install_openwrt_packages() {/,/^}/p' "$installer" | \
    sed "s|/etc/init.d/|$work/no-services/|g" > "$work/install-function"
. "$work/install-function"
first_existing_file() { return 1; }
download_file() {
    printf '%s\n' "$1" >> "$work/download-log"
    case "$1" in *manifest*) cp "$work/manifest" "$2" ;; *) cp "$work/package" "$2" ;; esac
}
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
release_download_base_url() { printf 'https://example.invalid'; }
SCRIPT_DIR="$work/no-local-packages"
TARGET_ARCH=aarch64_cortex-a53
for PACKAGE_MANAGER in opkg apk; do
    rm -f "$work/bin/opkg" "$work/bin/apk" "$work/install-log" "$work/download-log"
    ln -s "$work/manager" "$work/bin/$PACKAGE_MANAGER"
    [ "$PACKAGE_MANAGER" = opkg ] && PACKAGE_FORMAT=ipk || PACKAGE_FORMAT=apk
    install_openwrt_packages >/dev/null
    [ -s "$work/install-log" ]
    grep -q "agent.$PACKAGE_FORMAT" "$work/download-log"
    grep -q "luci.$PACKAGE_FORMAT" "$work/download-log"
done
sed 's/"stable"/"beta"/; s/"1.0.0"/"1.1.1-beta.5"/' "$work/manifest" > "$work/beta-manifest"
cp "$work/beta-manifest" "$work/manifest"
for PACKAGE_MANAGER in opkg apk; do
    rm -f "$work/bin/opkg" "$work/bin/apk" "$work/install-log" "$work/download-log"
    ln -s "$work/manager" "$work/bin/$PACKAGE_MANAGER"
    [ "$PACKAGE_MANAGER" = opkg ] && PACKAGE_FORMAT=ipk || PACKAGE_FORMAT=apk
    NETQMON_RELEASE_TAG=v1.1.1-beta.5
    install_openwrt_packages >/dev/null
    [ -s "$work/install-log" ]
    grep -q "agent.$PACKAGE_FORMAT" "$work/download-log"
    grep -q "luci.$PACKAGE_FORMAT" "$work/download-log"
done
unset NETQMON_RELEASE_TAG
install_openwrt_packages >/dev/null # A direct beta release URL also works.
NETQMON_RELEASE_TAG=v1.1.1
if install_openwrt_packages >/dev/null; then
    printf 'FAIL: stable tag unexpectedly accepted a beta-only manifest\n' >&2
    exit 1
fi
printf 'OpenWrt update and installer checks passed (real jsonfilter, opkg and apk).\n'
