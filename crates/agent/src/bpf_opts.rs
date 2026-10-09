//! Zeroed libbpf option structs.
//!
//! libbpf rejects an option struct with `EINVAL` (logging "has non-zero extra
//! bytes") when any byte past the last field it knows about is non-zero, which
//! is how it stays compatible with callers built against a newer header. The
//! generated bindings implement `Default` by zeroing the struct bytewise,
//! padding included, so these helpers start from that and only overwrite `sz`.
//!
//! Building the struct with `..Default::default()` instead moves it together
//! field by field and leaves the destination's trailing padding
//! uninitialized. libbpf-sys ships a single set of bindings generated for
//! x86_64, so on a target whose layout differs - notably 32-bit MIPS, where
//! `size_t` and pointers are four bytes - `size_of` exceeds the struct libbpf
//! knows and that uninitialized padding lands inside the range it checks.

use std::mem::size_of;

use libbpf_rs::libbpf_sys::{bpf_link_create_opts, bpf_map_batch_opts, bpf_map_create_opts};

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn map_create() -> bpf_map_create_opts {
    let mut opts = bpf_map_create_opts::default();
    opts.sz = size_of::<bpf_map_create_opts>() as _;
    opts
}

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn map_batch() -> bpf_map_batch_opts {
    let mut opts = bpf_map_batch_opts::default();
    opts.sz = size_of::<bpf_map_batch_opts>() as _;
    opts
}

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn link_create() -> bpf_link_create_opts {
    let mut opts = bpf_link_create_opts::default();
    opts.sz = size_of::<bpf_link_create_opts>() as _;
    opts
}
