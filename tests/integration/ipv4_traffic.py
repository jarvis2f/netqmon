#!/usr/bin/env python3
import argparse
import socket
import struct


def mac_bytes(address: str) -> bytes:
    return bytes.fromhex(address.replace(":", ""))


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def send_ip_traffic(source: str, destination: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind((source, 0))
        udp.sendto(b"netqmon-udp", (destination, 19090))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        tcp.bind((source, 0))
        tcp.settimeout(1)
        try:
            tcp.connect((destination, 18080))
        except OSError:
            # A SYN to a closed port is sufficient for the TC parser fixture.
            pass


def send_vlan_fixture(
    interface: str, source_mac: str, destination_mac: str, layers: int
) -> None:
    payload = b"vlan-flow"
    source_ip = socket.inet_aton("198.51.100.1")
    destination_ip = socket.inet_aton("198.51.100.2")
    source_port, destination_port = (41000, 42000) if layers == 1 else (45000, 46000)
    udp = (
        struct.pack(
            "!HHHH", source_port, destination_port, 8 + len(payload), 0
        )
        + payload
    )
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        source_ip,
        destination_ip,
    )
    ipv4 = ipv4_without_checksum[:10] + struct.pack(
        "!H", checksum(ipv4_without_checksum)
    ) + ipv4_without_checksum[12:]
    ethernet_vlan = mac_bytes(destination_mac) + mac_bytes(source_mac)
    if layers == 1:
        ethernet_vlan += struct.pack("!HHH", 0x8100, 42, 0x0800)
    else:
        ethernet_vlan += struct.pack("!HHHHH", 0x88A8, 100, 0x8100, 42, 0x0800)

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as packet:
        packet.bind((interface, 0))
        packet.send(ethernet_vlan + ipv4 + udp)


def send_counter_fixture(
    interface: str,
    source_mac: str,
    destination_mac: str,
    count: int,
    source_address: str,
    destination_address: str,
    source_port: int,
    destination_port: int,
) -> None:
    # Keep the Ethernet frame above the minimum size so skb->len is unambiguous.
    payload = b"C" * 32
    source_ip = socket.inet_aton(source_address)
    destination_ip = socket.inet_aton(destination_address)
    udp = struct.pack(
        "!HHHH", source_port, destination_port, 8 + len(payload), 0
    ) + payload
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        2,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        source_ip,
        destination_ip,
    )
    ipv4 = ipv4_without_checksum[:10] + struct.pack(
        "!H", checksum(ipv4_without_checksum)
    ) + ipv4_without_checksum[12:]
    frame = (
        mac_bytes(destination_mac)
        + mac_bytes(source_mac)
        + struct.pack("!H", 0x0800)
        + ipv4
        + udp
    )

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as packet:
        packet.bind((interface, 0))
        for _ in range(count):
            packet.send(frame)
    print(len(frame))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    ip_parser = subparsers.add_parser("ip")
    ip_parser.add_argument("source")
    ip_parser.add_argument("destination")

    vlan_parser = subparsers.add_parser("vlan")
    vlan_parser.add_argument("layers", type=int, choices=(1, 2))
    vlan_parser.add_argument("interface")
    vlan_parser.add_argument("source_mac")
    vlan_parser.add_argument("destination_mac")

    counter_parser = subparsers.add_parser("counter")
    counter_parser.add_argument("count", type=int)
    counter_parser.add_argument("interface")
    counter_parser.add_argument("source_mac")
    counter_parser.add_argument("destination_mac")
    counter_parser.add_argument("--source-address", default="203.0.113.1")
    counter_parser.add_argument("--destination-address", default="203.0.113.2")
    counter_parser.add_argument("--source-port", type=int, default=47000)
    counter_parser.add_argument("--destination-port", type=int, default=48000)

    args = parser.parse_args()
    if args.command == "ip":
        send_ip_traffic(args.source, args.destination)
    elif args.command == "vlan":
        send_vlan_fixture(
            args.interface,
            args.source_mac,
            args.destination_mac,
            args.layers,
        )
    else:
        send_counter_fixture(
            args.interface,
            args.source_mac,
            args.destination_mac,
            args.count,
            args.source_address,
            args.destination_address,
            args.source_port,
            args.destination_port,
        )


if __name__ == "__main__":
    main()
