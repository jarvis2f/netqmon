#!/usr/bin/env bash
set -euo pipefail

# No root, BPF syscalls, network changes or token-capable kernel required.
cd "$(dirname "$0")/../.."
token_test_dir=$(mktemp -d)
trap 'rm -rf "$token_test_dir"' EXIT
mkdir -p "$token_test_dir/obj"
make --no-print-directory -s -C crates/libbpf-sys/libbpf/src install \
    BUILD_STATIC_ONLY=y OBJDIR="$token_test_dir/obj" \
    DESTDIR="$token_test_dir" PREFIX=/ LIBDIR=
"${CC:-cc}" -O2 \
    -Icrates/libbpf-sys/libbpf/include \
    -Icrates/libbpf-sys/libbpf/include/uapi \
    tests/integration/bpf_token.c "$token_test_dir/libbpf.a" -lelf -lz \
    -Wl,--wrap=bpf_prog_load -Wl,--wrap=bump_rlimit_memlock \
    -o "$token_test_dir/token-test"
"$token_test_dir/token-test"
