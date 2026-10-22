#!/usr/bin/env bash
# Build both Agent and LuCI packages with an already extracted release SDK.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 SDK_DIRECTORY FEED_DIRECTORY ARTIFACT_DIRECTORY" >&2
  exit 2
fi

sdk_dir="$(realpath "$1")"
feed_dir="$(realpath "$2")"
mkdir -p "$3"
artifact_dir="$(realpath "$3")"
test -x "$sdk_dir/scripts/feeds"
test -f "$feed_dir/netqmon/Makefile"
test -f "$feed_dir/luci-app-netqmon/Makefile"

cd "$sdk_dir"
# Retain the release SDK's pinned feed revisions, using GitHub mirrors just as
# openwrt/gh-action-sdk does. Mixing snapshot feeds back in defeats the pin.
sed \
  -e 's,https://git.openwrt.org/feed/,https://github.com/openwrt/,' \
  -e 's,https://git.openwrt.org/openwrt/,https://github.com/openwrt/,' \
  -e 's,https://git.openwrt.org/project/,https://github.com/openwrt/,' \
  feeds.conf.default > feeds.conf
printf '\nsrc-link action %s\n' "$feed_dir" >> feeds.conf
./scripts/feeds update -a
./scripts/feeds install -p action -f netqmon luci-app-netqmon
printf '\nCONFIG_PACKAGE_netqmon-agent=m\nCONFIG_PACKAGE_luci-app-netqmon=m\n' >> .config
make defconfig
make -j"${BUILD_JOBS:-$(nproc)}" V=s \
  package/netqmon/compile package/luci-app-netqmon/compile

# A successful make must produce both packages, not just dependencies.
for package in netqmon-agent luci-app-netqmon; do
  test -n "$(find bin/packages -type f -name "$package*.apk" -print -quit)" || {
    echo "Missing APK for $package" >&2
    exit 1
  }
done
mkdir -p "$artifact_dir/bin"
cp -a bin/packages "$artifact_dir/bin/"
