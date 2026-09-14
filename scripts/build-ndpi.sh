#!/usr/bin/env sh
# Build the pinned LGPL nDPI shared library. Build tools must already be installed.
set -eu
prefix=${1:-/usr/local}
source_dir=$(mktemp -d)
trap 'rm -rf "$source_dir"' EXIT HUP INT TERM
revision=90090b9ae841fce67d00c52ac87e755dcea7c95f
git clone --quiet --depth 1 --branch 4.14 https://github.com/ntop/nDPI.git "$source_dir/ndpi"
git -C "$source_dir/ndpi" checkout --quiet "$revision"
cd "$source_dir/ndpi"
./autogen.sh --with-only-libndpi --prefix="$prefix"
make -j2
make install
mkdir -p "$prefix/share/licenses/ndpi"
cp COPYING "$prefix/share/licenses/ndpi/"
printf '%s\n' "nDPI 4.14 source: https://github.com/ntop/nDPI/tree/$revision" > "$prefix/share/licenses/ndpi/SOURCE"
