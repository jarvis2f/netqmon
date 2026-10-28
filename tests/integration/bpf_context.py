#!/usr/bin/env python3
"""Verify TC programs without kernel BTF context-name recognition (issue #7).

Run as root on Linux with clang and bpftool. Renaming the UAPI context makes
global skb arguments unrecognizable even on CI kernels with working BTF.
Static helpers still inherit the caller's context type. No live hooks change.
"""

import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
VARIANTS = {
    "default": [],
    "path": ["NETQMON_QOS_PATH_PROBE"],
    "poc": ["NETQMON_QOS_POC"],
    "priority": ["NETQMON_QOS_PATH_PROBE", "NETQMON_QOS_PRIORITY"],
    "all": ["NETQMON_QOS_PATH_PROBE", "NETQMON_QOS_PRIORITY", "NETQMON_QOS_POC"],
}
CLIENT_MAC = bytes.fromhex("020000000001")
REMOTE_MAC = bytes.fromhex("020000000002")


def find_bpftool():
    # Ubuntu's /usr/sbin wrapper can target a different running kernel.
    candidates = [shutil.which("bpftool")]
    candidates.extend(Path("/usr/lib/linux-tools").glob("**/bpftool"))
    for candidate in candidates:
        if candidate and subprocess.run([str(candidate), "version"], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL).returncode == 0:
            return str(candidate)
    raise SystemExit("A working bpftool executable is required")


BPFTOOL = find_bpftool()


def run(*args):
    return subprocess.check_output([str(arg) for arg in args], text=True)


def bpf(*args):
    return run(BPFTOOL, *args)


def update(path, key, value):
    bpf("map", "update", "pinned", path, "key", "hex", *key.hex(" ").split(),
        "value", "hex", *value.hex(" ").split())


def verdict(kind, tag=0):
    return (struct.pack("=QQ", time.monotonic_ns() + 60_000_000_000, 1)
            + bytes(32) + CLIENT_MAC + bytes(2) + struct.pack("=IB3x", tag, kind))


def check_policy(pins, work):
    maps = pins / "maps"
    bss = next(path for path in maps.iterdir() if path.name.endswith((".bss", "_bss")))
    update(bss, bytes(4), struct.pack("=B7xQ", 1, 1))
    original_mark = 0x123456
    original_priority = 7
    context = bytearray(192)
    struct.pack_into("=I", context, 8, original_mark)
    struct.pack_into("=I", context, 32, original_priority)
    (work / "ctx").write_bytes(context)

    for version in (4, 6):
        client = ipaddress.ip_address("192.0.2.1" if version == 4 else "2001:db8::1").packed
        remote = ipaddress.ip_address("198.51.100.2" if version == 4 else "2001:db8::2").packed
        for hook, program in ((1, "netqmon_ingress"), (2, "netqmon_egress")):
            source, destination = (client, remote) if hook == 1 else (remote, client)
            ports = (12345, 443) if hook == 1 else (443, 12345)
            ethernet = (REMOTE_MAC + CLIENT_MAC if hook == 1 else CLIENT_MAC + REMOTE_MAC)
            ethernet += struct.pack("!H", 0x800 if version == 4 else 0x86DD)
            udp = struct.pack("!HHHH", *ports, 8, 0)
            if version == 4:
                network = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0,
                                      source, destination)
            else:
                network = struct.pack("!IHBB16s16s", 6 << 28, 8, 17, 64, source, destination)
            (work / "packet").write_bytes(ethernet + network + udp)
            key = (struct.pack("=BBBBI", version, 17, 0, hook, 1)
                   + source.ljust(16, b"\0") + destination.ljust(16, b"\0")
                   + struct.pack("!HH", *ports))

            def packet(expected_action, expected_mark=original_mark):
                result = json.loads(bpf(
                    "-j", "prog", "run", "pinned", pins / "progs" / program,
                    "data_in", work / "packet", "ctx_in", work / "ctx",
                    "ctx_out", work / "ctx-out"))
                assert result["retval"] == expected_action, (version, hook, result)
                output = (work / "ctx-out").read_bytes()
                assert struct.unpack_from("=I", output, 8)[0] == expected_mark
                assert struct.unpack_from("=I", output, 32)[0] == original_priority

            packet(0)
            update(maps / "flow_verdict_map", key, verdict(1))
            packet(2)
            update(maps / "flow_verdict_map", key, verdict(2, 3))
            packet(0, original_mark | (3 << 25))
            bpf("map", "delete", "pinned", maps / "flow_verdict_map", "key", "hex",
                *key.hex(" ").split())
            endpoint = (struct.pack("!BBH", version, 17, 443) + client.ljust(16, b"\0")
                        + remote.ljust(16, b"\0") + CLIENT_MAC + bytes(2))
            update(maps / "endpoint_blocks", endpoint, verdict(1))
            packet(2)
            bpf("map", "delete", "pinned", maps / "endpoint_blocks", "key", "hex",
                *endpoint.hex(" ").split())
            packet(0)


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root")
    if not os.path.ismount("/sys/fs/bpf"):
        run("mount", "-t", "bpf", "bpf", "/sys/fs/bpf")
    with tempfile.TemporaryDirectory(prefix="netqmon-bpf-context-") as tmp:
        work = Path(tmp)
        clang = ["clang", "-O2", "-g", "-target", "bpf", "-mcpu=v3", "-Wall", "-Werror",
                 "-D__sk_buff=netqmon_test_skb", "-I", str(ROOT / "bpf/include")]
        # Prove that the test actually rejects the original global-ctx pattern.
        control = work / "control.c"
        control.write_text('#include "netqmon_bpf.h"\n'
                           '__attribute__((noinline)) int global_ctx(struct __sk_buff *skb) '
                           '{ return skb ? skb->len : 0; }\n'
                           'SEC("tc") int entry(struct __sk_buff *skb) { return global_ctx(skb); }\n'
                           'char LICENSE[] SEC("license") = "GPL";\n')
        run(*clang, "-c", control, "-o", work / "control.o")
        with tempfile.TemporaryDirectory(prefix="nqm-ctx-", dir="/sys/fs/bpf") as pin_dir:
            pins = Path(pin_dir)
            rejected = subprocess.run(
                [BPFTOOL, "prog", "loadall", str(work / "control.o"), str(pins / "control"),
                 "type", "classifier"], text=True, capture_output=True)
            assert rejected.returncode and "Caller passes invalid args" in rejected.stderr, rejected

        for name, defines in VARIANTS.items():
            obj = work / "flow.bpf.o"
            run(*clang, *(f"-D{define}=1" for define in defines), "-c", ROOT / "bpf/flow.bpf.c",
                "-o", obj)
            with tempfile.TemporaryDirectory(prefix="nqm-ctx-", dir="/sys/fs/bpf") as pin_dir:
                pins = Path(pin_dir)
                (pins / "maps").mkdir()
                try:
                    bpf("prog", "loadall", obj, pins / "progs", "type", "classifier",
                        "pinmaps", pins / "maps")
                    check_policy(pins, work)
                finally:
                    # bpffs files must be unlinked before removing their directories.
                    shutil.rmtree(pins / "progs", ignore_errors=True)
                    shutil.rmtree(pins / "maps", ignore_errors=True)
            print(f"{name}: context-independent loading and IPv4/IPv6 policy checks passed", flush=True)


if __name__ == "__main__":
    main()
