#!/bin/sh
set -eu

sources_file=${NETQMON_GEO_SOURCES_FILE:-/etc/netqmon/geo-sources.conf}
destination=${NETQMON_GEO_DIRECTORY:-/data/geo}

mkdir -p "$destination"
updated=0

checksum_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "sha256sum or shasum is required" >&2
        return 1
    fi
}

# If sources file does not exist, use default GeoLite2 sources
read_sources() {
    if [ -f "$sources_file" ]; then
        cat "$sources_file"
    else
        cat << 'EOF'
GeoLite2-City.mmdb https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb -
GeoLite2-ASN.mmdb https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb -
EOF
    fi
}

read_sources | while read -r filename url checksum extra; do
    case "$filename" in
        ''|'#'*) continue ;;
        *[!A-Za-z0-9._-]*|.*|*..*|*[!.]mmdb)
            echo "Invalid Geo database filename: $filename" >&2
            exit 2
            ;;
        *.mmdb) ;;
        *)
            echo "Invalid Geo database filename: $filename" >&2
            exit 2
            ;;
    esac
    if [ -z "${url:-}" ] || [ -z "${checksum:-}" ] || [ -n "${extra:-}" ]; then
        echo "Invalid source line for $filename; expected: filename.mmdb URL SHA256" >&2
        exit 2
    fi

    # If the URL is a DB-IP download web page, resolve direct download link
    case "$url" in
        *db-ip.com/db/download/*)
            page_content=$(curl --fail --location --retry 3 --silent --show-error -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "$url" 2>/dev/null || true)
            if [ -n "$page_content" ]; then
                resolved_link=$(printf '%s\n' "$page_content" | grep -o 'https://download\.db-ip\.com/free/dbip-[^"'\'']*\.mmdb\.gz' | head -n 1 || true)
                if [ -n "$resolved_link" ]; then
                    url="$resolved_link"
                fi
            fi
            ;;
    esac

    temporary=$(mktemp "$destination/.netqmon-geo.XXXXXX")
    temporary_dl="$temporary.download"
    trap 'rm -f "$temporary" "$temporary_dl"' EXIT HUP INT TERM

    curl --fail --location --retry 3 --silent --show-error \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
        -H "Referer: https://db-ip.com/" \
        --output "$temporary_dl" "$url"

    # Check if download is gzipped and decompress if necessary
    if gzip -t "$temporary_dl" >/dev/null 2>&1; then
        gzip -dc "$temporary_dl" > "$temporary"
        rm -f "$temporary_dl"
    else
        mv -f "$temporary_dl" "$temporary"
    fi

    if [ "$checksum" != "-" ]; then
        actual=$(checksum_file "$temporary")
        expected=$(printf '%s' "$checksum" | tr '[:upper:]' '[:lower:]')
        if [ "$actual" != "$expected" ]; then
            echo "SHA-256 mismatch for $filename" >&2
            exit 1
        fi
    fi

    chmod 0644 "$temporary"
    mv -f "$temporary" "$destination/$filename"
    trap - EXIT HUP INT TERM
    updated=$((updated + 1))
    echo "Updated $destination/$filename"
done

# If sources file was given but empty
if [ -f "$sources_file" ] && [ ! -s "$sources_file" ]; then
    echo "No Geo database sources configured" >&2
    exit 2
fi
