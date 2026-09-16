#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_variables))]

mod config;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod conntrack;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod device;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod dhcp;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod dhcp_event;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod diagnostics;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod discovery;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod discovery_event;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod dns_event;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod dns_observation;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod dns_parser;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod favicon_probe;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod flow;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod identity;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod lifecycle;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod normalization;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod probe;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod sample;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod telemetry;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod topology;
#[cfg(any(target_os = "linux", test, target_family = "unix"))]
mod transport;

#[cfg(target_os = "linux")]
#[allow(clippy::all, clippy::pedantic, dead_code, unused_imports, unsafe_code)]
mod bpf {
    include!(concat!(env!("OUT_DIR"), "/flow.skel.rs"));

    use std::mem::size_of;
    use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};

    use libbpf_rs::Program;

    pub fn attach_tcx(
        program: &Program<'_>,
        ifindex: i32,
        attach_type: libbpf_rs::libbpf_sys::bpf_attach_type,
        first: bool,
    ) -> libbpf_rs::Result<OwnedFd> {
        let options = libbpf_rs::libbpf_sys::bpf_link_create_opts {
            sz: size_of::<libbpf_rs::libbpf_sys::bpf_link_create_opts>() as _,
            flags: if first {
                libbpf_rs::libbpf_sys::BPF_F_BEFORE
            } else {
                0
            },
            ..Default::default()
        };
        let fd = unsafe {
            libbpf_rs::libbpf_sys::bpf_link_create(
                program.as_fd().as_raw_fd(),
                ifindex,
                attach_type,
                &raw const options,
            )
        };
        if fd < 0 {
            return Err(libbpf_rs::Error::from_raw_os_error(-fd));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() {
    use clap::Parser as _;

    let cli = config::Cli::parse();
    let command = cli.command.unwrap_or_default();
    match command {
        config::Command::Diagnostics(args) => {
            diagnostics::handle_command(args);
        }
        config::Command::Run => {
            let config = match config::AgentConfig::load(&cli) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("configuration error: {error:#}");
                    std::process::exit(2);
                }
            };
            if let Err(error) = linux::run(&config) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        config::Command::Doctor => {
            let config = match config::AgentConfig::load(&cli) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("configuration error: {error:#}");
                    std::process::exit(2);
                }
            };
            if !linux::doctor(&config) {
                std::process::exit(1);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    use clap::Parser as _;

    let cli = config::Cli::parse();
    if let Some(config::Command::Diagnostics(args)) = cli.command {
        diagnostics::handle_command(args);
        return;
    }
    if let Err(error) = config::AgentConfig::load(&cli) {
        eprintln!("configuration error: {error:#}");
        std::process::exit(2);
    }
    if cli.command == Some(config::Command::Doctor) {
        eprintln!("doctor requires Linux");
        std::process::exit(1);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::bpf::FlowSkelBuilder;

    #[test]
    fn creates_embedded_flow_skeleton_builder() {
        let _builder = FlowSkelBuilder::default();
    }
}
