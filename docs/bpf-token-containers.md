# BPF token delegation in unprivileged Incus containers

This deployment requires Linux 6.9+ on the host, TCX support, and an Incus
version providing `security.bpffs.delegate_*`. The container needs `CAP_BPF` in
the bpffs owning user namespace and `CAP_NET_ADMIN` in its network namespace.
Host LSM/seccomp policy must also permit these operations. A privileged
container or system-wide unprivileged BPF is not required.

For the standard agent using TCX in both directions, start with:

```yaml
security.bpffs.delegate_cmds: map_create,prog_load,btf_load,link_create,obj_get
security.bpffs.delegate_maps: hash,lru_hash,array,percpu_array,prog_array,ringbuf
security.bpffs.delegate_progs: sched_cls
security.bpffs.delegate_attachs: tcx_ingress,tcx_egress
```

`percpu_array` holds packet parsing context and `prog_array` holds tail-call
stages. Both are required even when packet sampling is disabled. Global data
uses array maps. `socket_filter` and `tracepoint` are not required for NetQmon's
programs. The patched embedded libbpf skips its incompatible initial probe and
recognizes the pre-6.9 features needed for global data. Optional unrelated
feature probes can still be denied without preventing loading.

This list covers the standard agent, not experimental QoS feature builds,
which have additional programs, maps and standalone probes.

Restart the container after changing delegation; these options are not live
updates. Ensure `/sys/fs/bpf` exists in the container; Incus mounts the delegated
filesystem there by default. If using `security.bpffs.path`, set
`LIBBPF_BPF_TOKEN_PATH` to that same path.

To force TCX for a manual test on OpenWrt, set the backend in a TOML file such
as `/etc/netqmon/agent.toml`. Pass the file explicitly with `--config`.

```toml
[bpf]
backend = "tcx"
```

Choose an actual capture interface in the container rather than assuming a
`br-lan` bridge exists. For example:

```sh
LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf \
  netqmon-agent --config /etc/netqmon/agent.toml --interface eth0 doctor
```

The packaged OpenWrt service uses automatic backend selection by default and
chooses TCX when its probe succeeds. LuCI and UCI currently expose no backend
selector.

Apply the same environment to the service when an explicit/custom path is
needed. Default `/sys/fs/bpf` discovery is optional, matching libbpf. An empty
`LIBBPF_BPF_TOKEN_PATH` disables tokens. An explicit non-empty path that cannot
provide a token fails, without retrying standalone map checks with system
privileges. Ordinary kernels/mounts without delegation retain the existing
system-capability path when the environment variable is unset.

## Verification

`doctor` reports token discovery, creates each required map with both token FD
and `BPF_F_TOKEN_FD`, loads the full programs/tail-call stages, and briefly
attaches a no-op program to verify both TCX hooks. Delegated loads use TCX
expected attach types; ordinary loads retain legacy `SEC("tc")` for older
OpenWrt kernels.

On a Linux 6.9+ host with the unprivileged container above:

1. Require token discovery, all six map types, full program loading and both
   TCX hooks to pass `doctor`. Use `strace -f -v -e trace=bpf` if needed.
2. Run the agent with the same configuration and verify live upload/download
   counters through both hooks, covering tail calls and global data.
3. Remove `prog_array` and restart the container: its map check and full load
   must fail. Restore it and repeat for `percpu_array`.
4. Test a nonexistent explicit token path: token discovery and map checks must
   fail without silently dropping the token requirement.
5. On an ordinary router without delegation, unset the environment variable
   and verify legacy TC/netlink loading and attachment still pass.

Compilation and simulated/unit tests on pre-6.9 kernels cannot establish actual
Incus token support. Containers share the host kernel; newer userspace alone
cannot supply BPF token or TCX support.

References: [Incus delegation](https://linuxcontainers.org/incus/docs/main/explanation/bpf-tokens/),
[Linux token checks](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/token.c),
[issue #10](https://github.com/jarvis2f/netqmon/issues/10).
