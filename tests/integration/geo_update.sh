#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fixture_directory=$(mktemp -d)
trap 'rm -rf "$fixture_directory"' EXIT

printf 'test mmdb payload\n' > "$fixture_directory/source.mmdb"
if command -v sha256sum >/dev/null 2>&1; then
  checksum=$(sha256sum "$fixture_directory/source.mmdb" | awk '{print $1}')
else
  checksum=$(shasum -a 256 "$fixture_directory/source.mmdb" | awk '{print $1}')
fi
printf 'Test-Country.mmdb file://%s %s\n' "$fixture_directory/source.mmdb" "$checksum" > "$fixture_directory/sources.conf"

NETQMON_GEO_SOURCES_FILE="$fixture_directory/sources.conf" \
NETQMON_GEO_DIRECTORY="$fixture_directory/output" \
  sh "$repository_root/scripts/geo/update.sh"

cmp "$fixture_directory/source.mmdb" "$fixture_directory/output/Test-Country.mmdb"
permissions=$(stat -c '%a' "$fixture_directory/output/Test-Country.mmdb" 2>/dev/null || stat -f '%Lp' "$fixture_directory/output/Test-Country.mmdb")
case "$permissions" in
  644|100644) ;;
  *) echo "unexpected Geo database permissions: $permissions" >&2; exit 1 ;;
esac

# Test gzip decompression support
gzip -c "$fixture_directory/source.mmdb" > "$fixture_directory/source.mmdb.gz"
printf 'Test-Gzip.mmdb file://%s -\n' "$fixture_directory/source.mmdb.gz" > "$fixture_directory/sources_gz.conf"
NETQMON_GEO_SOURCES_FILE="$fixture_directory/sources_gz.conf" \
NETQMON_GEO_DIRECTORY="$fixture_directory/output" \
  sh "$repository_root/scripts/geo/update.sh"
cmp "$fixture_directory/source.mmdb" "$fixture_directory/output/Test-Gzip.mmdb"

