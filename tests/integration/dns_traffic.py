#!/usr/bin/env python3
import argparse
import socket
import struct


DNS_PAYLOAD_LENGTH = 700


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


def dns_payload() -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question_name = b"\x07example\x04test\x00"
    question = question_name + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(
        "!HHIH4s", 1, 1, 300, 4, socket.inet_aton("203.0.113.10")
    )
    message = header + question + answer
    return message + b"D" * (DNS_PAYLOAD_LENGTH - len(message))


def udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack(
        "!HHHH", source_port, destination_port, 8 + len(payload), 0
    ) + payload


def tcp(source_port: int, destination_port: int) -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        0,
        0,
        5 << 4,
        0x10,
        1024,
        0,
        0,
    )


def ipv4(source: str, destination: str, protocol: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        7,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ipv6(source: str, destination: str, protocol: int, payload: bytes) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        protocol,
        64,
        socket.inet_pton(socket.AF_INET6, source),
        socket.inet_pton(socket.AF_INET6, destination),
    ) + payload


def send(
    interface: str,
    source_mac: str,
    destination_mac: str,
    family: int,
    fixture: str,
) -> None:
    ethernet_protocol = 0x0800 if family == 4 else 0x86DD
    ethernet = (
        mac_bytes(destination_mac)
        + mac_bytes(source_mac)
        + struct.pack("!H", ethernet_protocol)
    )
    if family == 4:
        build_ip = lambda protocol, payload: ipv4(
            "198.51.100.53", "198.51.100.20", protocol, payload
        )
    else:
        build_ip = lambda protocol, payload: ipv6(
            "2001:db8:53::53", "2001:db8:53::20", protocol, payload
        )

    if fixture == "noise":
        packets = [
            build_ip(socket.IPPROTO_UDP, udp(40000, 53, b"query")),
            build_ip(socket.IPPROTO_TCP, tcp(53, 53000)),
        ]
    else:
        packets = [build_ip(socket.IPPROTO_UDP, udp(53, 53000, dns_payload()))]

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as packet:
        packet.bind((interface, 0))
        for contents in packets:
            packet.send(ethernet + contents)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", choices=("noise", "response"))
    parser.add_argument("family", type=int, choices=(4, 6))
    parser.add_argument("interface")
    parser.add_argument("source_mac")
    parser.add_argument("destination_mac")
    args = parser.parse_args()
    send(
        args.interface,
        args.source_mac,
        args.destination_mac,
        args.family,
        args.fixture,
    )


if __name__ == "__main__":
    main()
