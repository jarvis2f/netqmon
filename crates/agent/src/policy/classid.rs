//! Numeric class IDs shared with BPF, independent of legacy mark/tag encoding.
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/qos_classid.rs"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClassId(u32);

impl ClassId {
    pub(crate) fn leaf(major: u32, minor: u32) -> Result<Self, &'static str> {
        let allocated_leaf = minor == BYPASS_MINOR
            || (DEFAULT_FIRST..=DEFAULT_LAST).contains(&minor)
            || (APPLICATION_FIRST..=APPLICATION_LAST).contains(&minor);
        if !matches!(major, DOWNLOAD_MAJOR | UPLOAD_MAJOR) || !allocated_leaf {
            return Err("invalid QoS leaf classid");
        }
        Ok(Self((major << 16) | minor))
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for ClassId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}:{:x}", self.0 >> 16, self.0 & 0xffff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_text_and_bpf_numeric_handles_agree() {
        for (major, prefix) in [(DOWNLOAD_MAJOR, "51"), (UPLOAD_MAJOR, "52")] {
            for minor in [
                POC_LEAF_MINOR,
                APPLICATION_FIRST,
                APPLICATION_LAST,
                BYPASS_MINOR,
            ] {
                let id = ClassId::leaf(major, minor).unwrap();
                let text = id.to_string();
                let (a, b) = text.split_once(':').unwrap();
                assert_eq!(a, prefix);
                assert_eq!(
                    id.raw(),
                    (u32::from_str_radix(a, 16).unwrap() << 16)
                        | u32::from_str_radix(b, 16).unwrap()
                );
            }
        }
        assert_eq!(
            ClassId::leaf(DOWNLOAD_MAJOR, BYPASS_MINOR).unwrap().raw(),
            0x0051_fffe
        );
        assert_eq!(
            ClassId::leaf(UPLOAD_MAJOR, POC_LEAF_MINOR).unwrap().raw(),
            0x0052_0200
        );
    }

    #[test]
    fn direct_queue_root_and_overflow_are_not_leaf_targets() {
        for major in [DOWNLOAD_MAJOR, UPLOAD_MAJOR] {
            for minor in [
                0,
                ROOT_MINOR,
                CLIENT_FIRST,
                CLIENT_LAST,
                DEFAULT_LAST + 1,
                APPLICATION_FIRST - 1,
                APPLICATION_LAST + 1,
                0xffff,
                0x1_0000,
            ] {
                assert!(ClassId::leaf(major, minor).is_err());
            }
        }
        assert!(ClassId::leaf(51, POC_LEAF_MINOR).is_err());
        assert!(ClassId::leaf(52, POC_LEAF_MINOR).is_err());
    }

    #[test]
    fn allocated_ranges_do_not_overlap_reserved_or_other_classes() {
        let ranges = [
            (CLIENT_FIRST, CLIENT_LAST),
            (DEFAULT_FIRST, DEFAULT_LAST),
            (APPLICATION_FIRST, APPLICATION_LAST),
        ];
        for (i, &(first, last)) in ranges.iter().enumerate() {
            assert!(first <= last && last < BYPASS_MINOR);
            assert!(first > ROOT_MINOR);
            for &(other_first, other_last) in &ranges[i + 1..] {
                assert!(last < other_first || other_last < first);
            }
        }
    }
}
