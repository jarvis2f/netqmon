#!/usr/bin/env python3
import argparse
import socket
import struct


def mac_bytes(address: str) -> bytes:
    return bytes.fromhex(address.replace(":", ""))


def send_ip_traffic(source: str, destination: str) -> None:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
        udp.bind((source, 0))
        udp.sendto(b"netqmon-ipv6-udp", (destination, 19091))

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as tcp:
        tcp.bind((source, 0))
        tcp.settimeout(1)
        try:
            tcp.connect((destination, 18081))
        except OSError:
            # A SYN to a closed port is sufficient for the TC parser fixture.
            pass


def ipv6_header(source: str, destination: str, next_header: int, length: int) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        length,
        next_header,
        64,
        socket.inet_pton(socket.AF_INET6, source),
        socket.inet_pton(socket.AF_INET6, destination),
    )


def send_raw_fixture(
    interface: str, source_mac: str, destination_mac: str, fixture: str
) -> None:
    udp = struct.pack("!HHHH", 43000, 44000, 8, 0)
    if fixture == "extension":
        extension = struct.pack("!BB6s", socket.IPPROTO_UDP, 0, b"\0" * 6)
        payload = extension + udp
        ipv6 = ipv6_header("2001:db8:2::1", "2001:db8:2::2", 60, len(payload))
    else:
        fragment = struct.pack("!BBHI", socket.IPPROTO_UDP, 0, 8, 12345)
        payload = fragment + udp
        ipv6 = ipv6_header("2001:db8:3::1", "2001:db8:3::2", 44, len(payload))

    ethernet = (
        mac_bytes(destination_mac)
        + mac_bytes(source_mac)
        + struct.pack("!H", 0x86DD)
    )
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as packet:
        packet.bind((interface, 0))
        packet.send(ethernet + ipv6 + payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    ip_parser = subparsers.add_parser("ip")
    ip_parser.add_argument("source")
    ip_parser.add_argument("destination")

    raw_parser = subparsers.add_parser("raw")
    raw_parser.add_argument("fixture", choices=("extension", "fragment"))
    raw_parser.add_argument("interface")
    raw_parser.add_argument("source_mac")
    raw_parser.add_argument("destination_mac")

    args = parser.parse_args()
    if args.command == "ip":
        send_ip_traffic(args.source, args.destination)
    else:
        send_raw_fixture(
            args.interface,
            args.source_mac,
            args.destination_mac,
            args.fixture,
        )


if __name__ == "__main__":
    main()
