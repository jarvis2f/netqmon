# NetQmon's libbpf token compatibility patch

Default-build inputs from crates.io `libbpf-sys 1.7.0+v1.7.0`, package SHA-256
`a109478760b2900aa2a6f2087e9d0de1d9c535b1758602af2845d5d2ccfaed7c`.
Original bindings, headers, licenses and libbpf checkpoint IDs are retained.
The workspace `[patch.crates-io]` applies to libbpf-rs and libbpf-cargo, including
static releases and cross builds. Existing Dockerfiles copy the `crates` tree.

Changes to upstream files are recorded in `token-compat.patch`:

- `libbpf/src/libbpf.c`: backport Linux commit
  [d262a25d8b58](https://git.kernel.org/torvalds/c/d262a25d8b58b697b2a1a2fe4b0078446cc00e11)
  to skip preliminary program loading when using a token.
- `libbpf/src/features.c`: recognize program names, global data and expected
  attach types when using a token. All predate Linux 6.9 (the token baseline);
  denied SOCKET_FILTER/CGROUP_SOCK probes must not disable these features.
  Other feature probes remain unchanged.
- `build.rs`: explicitly reject vendored-libelf/vendored-zlib. Those optional
  source trees and upstream tests/maintenance files are omitted. NetQmon uses
  system libelf/zlib; static linking to those libraries remains supported.

Remove this override when a published dependency includes equivalent support.
Verify global data as well as initial program loading before doing so.
See [deployment and verification](../../docs/bpf-token-containers.md).
