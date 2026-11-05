//! Match libbpf's implicit/explicit token discovery for standalone map probes.

use std::fs::OpenOptions;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::{ErrorExt as _, OpenObject, ProgramAttachType, ProgramType, libbpf_sys};

pub(super) struct BpfToken(OwnedFd);

impl BpfToken {
    pub(super) fn discover() -> libbpf_rs::Result<Option<Self>> {
        Self::at(std::env::var_os("LIBBPF_BPF_TOKEN_PATH").map(PathBuf::from))
    }

    fn at(path: Option<PathBuf>) -> libbpf_rs::Result<Option<Self>> {
        // An explicitly empty path disables tokens, just as in libbpf.
        if path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Ok(None);
        }
        let mandatory = path.is_some();
        let result = (|| {
            let path = path.unwrap_or_else(|| PathBuf::from("/sys/fs/bpf"));
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_DIRECTORY)
                .open(&path)
                .with_context(|| format!("open bpffs directory {}", path.display()))?;
            // SAFETY: directory remains open for the call; libbpf takes no ownership.
            let fd = unsafe {
                libbpf_sys::bpf_token_create(directory.as_raw_fd(), std::ptr::null_mut())
            };
            if fd < 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-fd).context("BPF_TOKEN_CREATE"));
            }
            // SAFETY: successful BPF_TOKEN_CREATE returns a new owned FD.
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        })();
        match result {
            Ok(token) => Ok(Some(token)),
            Err(error) if mandatory => Err(error),
            // Ordinary OpenWrt kernels/mounts need no token. libbpf also treats
            // default-path discovery as optional, including on pre-6.9 kernels.
            Err(_) => Ok(None),
        }
    }

    pub(super) fn map_options(&self) -> libbpf_sys::bpf_map_create_opts {
        let mut options = super::map_options::map_create_options();
        options.token_fd = u32::try_from(self.0.as_raw_fd()).expect("owned FDs are nonnegative");
        options.map_flags |= libbpf_sys::BPF_F_TOKEN_FD;
        options
    }
}

/// Keep legacy SEC("tc") on ordinary kernels, but load delegated programs with
/// an attach type actually granted by a TCX-only token. Includes tail-call stages.
fn configure_programs(object: &mut OpenObject) {
    for mut program in object.progs_mut() {
        if program.prog_type() == ProgramType::SchedCls {
            let attach_type = if program.name().as_encoded_bytes().ends_with(b"_egress") {
                ProgramAttachType::TcxEgress
            } else {
                // The no-op attach probe is shared by both hooks. TCX permits
                // attaching a SCHED_CLS program to either hook on token kernels.
                ProgramAttachType::TcxIngress
            };
            program.set_attach_type(attach_type);
        }
    }
}

pub(super) fn load<'obj, S: OpenSkel<'obj>>(mut skeleton: S) -> libbpf_rs::Result<S::Output> {
    if BpfToken::discover()?.is_some() {
        configure_programs(skeleton.open_object_mut());
    }
    skeleton.load()
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use libbpf_rs::AsRawLibbpf as _;
    use libbpf_rs::skel::SkelBuilder as _;

    use super::*;
    use crate::bpf::FlowSkelBuilder;

    #[test]
    fn explicit_token_path_failure_is_not_silently_ignored() {
        let directory = tempfile::tempdir().unwrap();
        assert!(BpfToken::at(Some(directory.path().join("missing"))).is_err());
        assert!(BpfToken::at(Some(PathBuf::new())).unwrap().is_none());
    }

    #[test]
    fn existing_directory_reaches_token_creation() {
        // A regular directory can be opened but cannot supply a BPF token.
        // This works on kernels without token support and catches O_RDWR/EISDIR.
        let directory = tempfile::tempdir().unwrap();
        let error = BpfToken::at(Some(directory.path().to_owned()))
            .err()
            .expect("a regular directory cannot supply a token");
        assert!(error.to_string().starts_with("BPF_TOKEN_CREATE"), "{error}");
    }

    #[test]
    fn standalone_maps_pass_both_token_fd_and_flag() {
        // Only checks construction of options; no BPF syscall with this FD.
        let token = BpfToken(tempfile::tempfile().unwrap().into());
        let options = token.map_options();
        assert_eq!(
            options.token_fd,
            u32::try_from(token.0.as_raw_fd()).unwrap()
        );
        assert_ne!(options.map_flags & libbpf_sys::BPF_F_TOKEN_FD, 0);
        assert_eq!(
            options.sz,
            super::super::map_options::map_create_options().sz
        );
    }

    #[test]
    fn delegated_load_sets_attach_types_for_every_tail_call_stage() {
        let mut object = MaybeUninit::uninit();
        let mut skeleton = FlowSkelBuilder::default().open(&mut object).unwrap();
        // Ordinary builds must retain the legacy attach type for old kernels.
        for program in skeleton.open_object().progs() {
            assert_eq!(
                unsafe {
                    libbpf_sys::bpf_program__expected_attach_type(
                        program.as_libbpf_object().as_ptr(),
                    )
                },
                libbpf_sys::BPF_CGROUP_INET_INGRESS
            );
        }
        configure_programs(skeleton.open_object_mut());
        let mut count = 0;
        for program in skeleton.open_object().progs() {
            count += 1;
            let expected = if program.name().as_encoded_bytes().ends_with(b"_egress") {
                ProgramAttachType::TcxEgress
            } else {
                ProgramAttachType::TcxIngress
            };
            assert_eq!(
                unsafe {
                    libbpf_sys::bpf_program__expected_attach_type(
                        program.as_libbpf_object().as_ptr(),
                    )
                },
                expected as u32,
                "{:?}",
                program.name()
            );
        }
        assert!(count >= 3);
    }
}
