#!/usr/bin/env python3
"""
Transparent Proxy Workload and Echo Server for Netqmon E2E & Integration testing.
Supports:
- Server mode: binds to local TCP/UDP port and echoes incoming payloads back to client.
- Client mode: sends TCP/UDP data to specified target and port, with optional payload repetition.
- Dual-stack IPv4 and IPv6.
"""

import argparse
import socket
import sys
import time

def run_server(protocol: str, family: str, port: int):
    af = socket.AF_INET6 if family == "6" else socket.AF_INET
    bind_addr = "::" if family == "6" else "0.0.0.0"

    if protocol == "tcp":
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_addr, port))
        sock.listen(128)
        print(f"TCP server listening on {bind_addr}:{port}", flush=True)
        while True:
            try:
                conn, addr = sock.accept()
                data = conn.recv(4096)
                if data:
                    conn.sendall(data)
                conn.close()
            except Exception as e:
                break
    elif protocol == "udp":
        sock = socket.socket(af, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_addr, port))
        print(f"UDP server listening on {bind_addr}:{port}", flush=True)
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                if data:
                    sock.sendto(data, addr)
            except Exception as e:
                break

def run_client(protocol: str, host: str, port: int, count: int, payload_size: int):
    # Detect address family from host
    is_ipv6 = ":" in host
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    payload = b"X" * payload_size

    for i in range(count):
        if protocol == "tcp":
            try:
                sock = socket.socket(af, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((host, port))
                sock.sendall(payload)
                resp = sock.recv(4096)
                sock.close()
            except Exception as e:
                print(f"TCP client error ({i+1}/{count}): {e}", file=sys.stderr, flush=True)
        elif protocol == "udp":
            try:
                sock = socket.socket(af, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                sock.sendto(payload, (host, port))
                try:
                    resp, _ = sock.recvfrom(4096)
                except socket.timeout:
                    pass
                sock.close()
            except Exception as e:
                print(f"UDP client error ({i+1}/{count}): {e}", file=sys.stderr, flush=True)
        if count > 1:
            time.sleep(0.01)

def main():
    parser = argparse.ArgumentParser(description="Transparent proxy test workload helper")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Server parser
    server_parser = subparsers.add_parser("server")
    server_parser.add_argument("--protocol", choices=["tcp", "udp"], required=True)
    server_parser.add_argument("--family", choices=["4", "6"], default="4")
    server_parser.add_argument("--port", type=int, required=True)

    # Client parser
    client_parser = subparsers.add_parser("client")
    client_parser.add_argument("--protocol", choices=["tcp", "udp"], required=True)
    client_parser.add_argument("--host", required=True)
    client_parser.add_argument("--port", type=int, required=True)
    client_parser.add_argument("--count", type=int, default=1)
    client_parser.add_argument("--payload-size", type=int, default=64)

    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.protocol, args.family, args.port)
    elif args.mode == "client":
        run_client(args.protocol, args.host, args.port, args.count, args.payload_size)

if __name__ == "__main__":
    main()
