use std::mem::{offset_of, size_of};

use libbpf_rs::libbpf_sys::bpf_map_create_opts;

pub(super) fn map_create_options() -> bpf_map_create_opts {
    bpf_map_create_opts {
        // libbpf validates bytes after its last known field up to `sz`.
        // The pregenerated bindings add explicit padding that grows this struct
        // to 72 bytes on 32-bit MIPS/ARM, while the C fields end at byte 64.
        // Rust moves need not preserve zeroes in the resulting implicit tail
        // padding, even with Default::default(). Exclude padding from `sz`.
        sz: (offset_of!(bpf_map_create_opts, excl_prog_hash_size) + size_of::<u32>()) as _,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::map_create_options;

    #[test]
    fn map_options_size_matches_libbpf_field_boundary() {
        // C bpf.h ends at byte 64 on these 32-bit ABIs and byte 68 on 64-bit.
        // In particular, sizeof the pregenerated Rust struct is 72 on both.
        #[cfg(any(target_arch = "mips", target_arch = "arm"))]
        assert_eq!(map_create_options().sz, 64);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(map_create_options().sz, 68);
    }
}
