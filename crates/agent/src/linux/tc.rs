use std::os::fd::{BorrowedFd, OwnedFd};

use anyhow::{Result, bail};
use libbpf_rs::{Program, TC_EGRESS, TC_INGRESS, TcHook, TcHookBuilder};

use crate::bpf;
use crate::config::{AttachBackend, AttachOrder, TcxOrder};

const NETQMON_TC_PROBE_HANDLE: u32 = 0x4e51_4d44;
const NETQMON_TC_PROBE_PRIORITY: u32 = 0x7ffe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ActiveBackend {
    Tcx,
    Netlink,
}

impl std::fmt::Display for ActiveBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Tcx => "tcx",
            Self::Netlink => "netlink",
        })
    }
}

pub(super) enum AttachLinks {
    Tcx(TcxLinks),
    Netlink(NetlinkHooks),
}

impl AttachLinks {
    pub(super) fn backend(&self) -> ActiveBackend {
        match self {
            Self::Tcx(_) => ActiveBackend::Tcx,
            Self::Netlink(_) => ActiveBackend::Netlink,
        }
    }

    pub(super) fn detach(&mut self) -> Result<()> {
        match self {
            Self::Tcx(links) => {
                links.detach();
                Ok(())
            }
            Self::Netlink(hooks) => hooks.detach(),
        }
    }
}

pub(super) struct TcxLinks {
    ingress: Option<OwnedFd>,
    egress: Option<OwnedFd>,
}

impl TcxLinks {
    pub(super) fn attach(
        ifindex: i32,
        ingress_program: &Program<'_>,
        egress_program: &Program<'_>,
        order: AttachOrder,
        attach_ingress: bool,
        attach_egress: bool,
    ) -> libbpf_rs::Result<Self> {
        let first = order.tcx_order == TcxOrder::First;
        let ingress = if attach_ingress {
            Some(bpf::attach_tcx(
                ingress_program,
                ifindex,
                libbpf_rs::libbpf_sys::BPF_TCX_INGRESS,
                first,
            )?)
        } else {
            None
        };
        let egress = if attach_egress {
            match bpf::attach_tcx(
                egress_program,
                ifindex,
                libbpf_rs::libbpf_sys::BPF_TCX_EGRESS,
                first,
            ) {
                Ok(link) => Some(link),
                Err(error) => {
                    drop(ingress);
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok(Self { ingress, egress })
    }

    pub(super) fn detach(&mut self) {
        self.egress.take();
        self.ingress.take();
    }
}

pub(super) struct NetlinkHooks {
    ingress: TcHook,
    egress: TcHook,
    ingress_attached: bool,
    egress_attached: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NetlinkOptions {
    handle: u32,
    priority: u32,
}

impl NetlinkHooks {
    pub(super) fn attach(
        ifindex: i32,
        ingress_program_fd: BorrowedFd<'_>,
        egress_program_fd: BorrowedFd<'_>,
        order: AttachOrder,
        attach_ingress: bool,
        attach_egress: bool,
    ) -> libbpf_rs::Result<Self> {
        Self::attach_with_options(
            ifindex,
            ingress_program_fd,
            egress_program_fd,
            NetlinkOptions {
                handle: order.tc_handle,
                priority: order.tc_priority,
            },
            attach_ingress,
            attach_egress,
        )
    }

    pub(super) fn attach_probe(
        ifindex: i32,
        program_fd: BorrowedFd<'_>,
    ) -> libbpf_rs::Result<Self> {
        Self::attach_with_options(
            ifindex,
            program_fd,
            program_fd,
            NetlinkOptions {
                handle: NETQMON_TC_PROBE_HANDLE,
                priority: NETQMON_TC_PROBE_PRIORITY,
            },
            true,
            true,
        )
    }

    fn attach_with_options(
        ifindex: i32,
        ingress_program_fd: BorrowedFd<'_>,
        egress_program_fd: BorrowedFd<'_>,
        options: NetlinkOptions,
        attach_ingress: bool,
        attach_egress: bool,
    ) -> libbpf_rs::Result<Self> {
        let mut ingress_builder = TcHookBuilder::new(ingress_program_fd);
        ingress_builder
            .ifindex(ifindex)
            .replace(false)
            .handle(options.handle)
            .priority(options.priority);
        let mut egress_builder = TcHookBuilder::new(egress_program_fd);
        egress_builder
            .ifindex(ifindex)
            .replace(false)
            .handle(options.handle)
            .priority(options.priority);
        let mut hooks = Self {
            ingress: ingress_builder.hook(TC_INGRESS),
            egress: egress_builder.hook(TC_EGRESS),
            ingress_attached: false,
            egress_attached: false,
        };
        hooks.ingress.create()?;
        if attach_ingress {
            hooks.ingress.attach()?;
            hooks.ingress_attached = true;
        }
        if attach_egress {
            if let Err(error) = hooks.egress.attach() {
                if hooks.ingress_attached {
                    let _ = hooks.ingress.detach();
                }
                hooks.ingress_attached = false;
                return Err(error);
            }
            hooks.egress_attached = true;
        }
        Ok(hooks)
    }

    pub(super) fn detach(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if self.egress_attached {
            match self.egress.detach() {
                Ok(()) => self.egress_attached = false,
                Err(error) => errors.push(format!("egress: {error}")),
            }
        }
        if self.ingress_attached {
            match self.ingress.detach() {
                Ok(()) => self.ingress_attached = false,
                Err(error) => errors.push(format!("ingress: {error}")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("failed to detach TC hooks: {}", errors.join(", "))
        }
    }
}

impl Drop for NetlinkHooks {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

pub(super) fn requested_backend(value: AttachBackend, tcx_supported: bool) -> ActiveBackend {
    match value {
        AttachBackend::Tcx => ActiveBackend::Tcx,
        AttachBackend::Auto if tcx_supported => ActiveBackend::Tcx,
        AttachBackend::Netlink | AttachBackend::Auto => ActiveBackend::Netlink,
    }
}

#[cfg(test)]
mod tests {
    use super::{ActiveBackend, requested_backend};
    use crate::config::AttachBackend;

    #[test]
    fn auto_prefers_tcx_and_falls_back_to_netlink() {
        assert_eq!(
            requested_backend(AttachBackend::Auto, true),
            ActiveBackend::Tcx
        );
        assert_eq!(
            requested_backend(AttachBackend::Auto, false),
            ActiveBackend::Netlink
        );
        assert_eq!(
            requested_backend(AttachBackend::Netlink, true),
            ActiveBackend::Netlink
        );
    }
}
