#!/usr/bin/env python3
"""Synthetic, non-sensitive, bidirectional IP packets for sample budget tests."""
import socket
import struct
import sys
from ipv4_traffic import checksum

interface, source_mac, destination_mac, version = sys.argv[1:]
version = int(version)
mac = lambda value: bytes.fromhex(value.replace(':', ''))
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
    sock.bind((interface, 0))
    for i in range(40):
        reverse = i % 2 == 1
        source, destination = ('192.0.2.2', '198.51.100.1') if version == 4 else ('2001:db8:1::2', '2001:db8:2::1')
        sp, dp = (50000, 50001)
        if reverse:
            source, destination, sp, dp = destination, source, dp, sp
        udp = struct.pack('!HHHH', sp, dp, 608, 0) + b'S' * 600
        if version == 4:
            header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 628, i, 0, 64, 17, 0, socket.inet_aton(source), socket.inet_aton(destination))
            header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        else:
            header = struct.pack('!IHBB16s16s', 6 << 28, len(udp), 17, 64, socket.inet_pton(socket.AF_INET6, source), socket.inet_pton(socket.AF_INET6, destination))
        ethernet = mac(destination_mac) + mac(source_mac) + struct.pack('!H', 0x0800 if version == 4 else 0x86DD)
        sock.send(ethernet + header + udp)
