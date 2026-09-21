#!/usr/bin/env python3
"""
Netqmon Controller Synthetic Demo Database Generator.

Generates a 100% synthetic, realistic SQLite database template for public demo deployment.
Strictly adheres to zero user data reading:
- Does NOT read any existing netqmon.db or user database.
- Does NOT sanitize or copy local network information.
- All MACs are locally administered unicast (02:00:00:00:00:xx).
- All private IPs are strictly within 192.168.50.0/24.
- Generates realistic diurnal traffic curves, device identities, and global internet destinations.
- Schema is directly applied from migrations/sqlite/*.sql to guarantee 100% compatibility.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import random
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Fixed Demo Time Base: 2024-01-03 00:00:00 UTC
TARGET_MAX_TIMESTAMP_MS = 1704240000000

DEMO_GATEWAY_ID = "demo-gateway"
DEMO_GATEWAY_NAME = "Demo Gateway"
DEMO_GATEWAY_TOKEN_HASH = hashlib.sha256(b"netqmon-demo-gateway-token").digest()


@dataclass
class SyntheticDevice:
    id: int
    name: str
    hostname: str
    mac_bytes: bytes
    ip_bytes: bytes
    ip_str: str
    vendor: str
    device_type: str
    os_family: str
    model: str
    evidence_sources: List[Dict[str, Any]]
    first_seen_offset_hours: float
    apps_affinity: List[str]
    traffic_weight: float
    active_hours: Tuple[int, int]  # (start_hour, end_hour) daily


@dataclass
class SyntheticApp:
    app_id: str
    name: str
    category_id: str
    organization_id: str
    protocol: int  # 6 = TCP, 17 = UDP
    protocol_id: str
    domains: List[str]
    remote_ips: List[str]  # Real public IPs
    default_port: int
    traffic_role: str
    base_upload_ratio: float  # upload / total
    bytes_range: Tuple[int, int]  # (min_bytes_per_min, max_bytes_per_min)
    classification_reason: str


def ip_to_bytes(ip_str: str) -> bytes:
    return ipaddress.ip_address(ip_str).packed


def mac_to_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", "").replace("-", ""))


def format_ip_bytes(b: bytes) -> str:
    return str(ipaddress.ip_address(b))


def format_flow_id(
    gateway_id: str,
    ip_version: int,
    protocol: int,
    client_ip: bytes,
    client_port: int,
    remote_ip: bytes,
    remote_port: int,
    direction: int,
) -> str:
    client_hex = ", ".join(f"{b:02x}" for b in client_ip)
    remote_hex = ", ".join(f"{b:02x}" for b in remote_ip)
    return (
        f"{gateway_id}:{ip_version}:{protocol}:[{client_hex}]:"
        f"{client_port}:[{remote_hex}]:{remote_port}:{direction}"
    )


def create_synthetic_devices(start_time_ms: int, end_time_ms: int) -> List[SyntheticDevice]:
    devices = [
        SyntheticDevice(
            id=1,
            name="MacBook Pro 16",
            hostname="demo-macbook-pro",
            mac_bytes=mac_to_bytes("02:00:00:00:00:01"),
            ip_bytes=ip_to_bytes("192.168.50.10"),
            ip_str="192.168.50.10",
            vendor="Apple",
            device_type="laptop",
            os_family="macOS",
            model="MacBookPro18,1",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-macbook-pro", "confidence": 0.95},
                {"source": "dhcp", "field": "vendor", "value": "Apple Inc.", "confidence": 0.90},
                {"source": "mdns", "field": "model", "value": "MacBookPro18,1", "confidence": 0.98},
                {"source": "mdns", "field": "os_family", "value": "macOS", "confidence": 0.95},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["github", "openai", "slack", "youtube", "spotify", "notion", "docker-hub", "nas-smb"],
            traffic_weight=1.5,
            active_hours=(9, 23),
        ),
        SyntheticDevice(
            id=2,
            name="iPhone 15 Pro",
            hostname="demo-iphone-15",
            mac_bytes=mac_to_bytes("02:00:00:00:00:02"),
            ip_bytes=ip_to_bytes("192.168.50.11"),
            ip_str="192.168.50.11",
            vendor="Apple",
            device_type="mobile",
            os_family="iOS",
            model="iPhone16,1",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-iphone-15", "confidence": 0.95},
                {"source": "mdns", "field": "model", "value": "iPhone16,1", "confidence": 0.98},
                {"source": "mdns", "field": "os_family", "value": "iOS", "confidence": 0.95},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["wechat", "bilibili", "apple-music", "icloud", "telegram", "reddit", "youtube"],
            traffic_weight=1.0,
            active_hours=(7, 24),
        ),
        SyntheticDevice(
            id=3,
            name="ThinkPad X1 Carbon",
            hostname="demo-thinkpad-x1",
            mac_bytes=mac_to_bytes("02:00:00:00:00:03"),
            ip_bytes=ip_to_bytes("192.168.50.12"),
            ip_str="192.168.50.12",
            vendor="Lenovo",
            device_type="desktop",
            os_family="Windows",
            model="ThinkPad X1 Carbon Gen 10",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-thinkpad-x1", "confidence": 0.92},
                {"source": "dhcp", "field": "os_family", "value": "Windows", "confidence": 0.88},
                {"source": "upnp", "field": "vendor", "value": "Lenovo", "confidence": 0.90},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["microsoft-365", "github", "slack", "notion", "wikipedia", "youtube"],
            traffic_weight=1.2,
            active_hours=(9, 19),
        ),
        SyntheticDevice(
            id=4,
            name="iPad Air",
            hostname="demo-ipad-air",
            mac_bytes=mac_to_bytes("02:00:00:00:00:04"),
            ip_bytes=ip_to_bytes("192.168.50.13"),
            ip_str="192.168.50.13",
            vendor="Apple",
            device_type="tablet",
            os_family="iPadOS",
            model="iPad13,16",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-ipad-air", "confidence": 0.95},
                {"source": "mdns", "field": "model", "value": "iPad13,16", "confidence": 0.98},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["bilibili", "youtube", "netflix", "wikipedia", "apple-music"],
            traffic_weight=0.8,
            active_hours=(12, 23),
        ),
        SyntheticDevice(
            id=5,
            name="Ubuntu Home Server",
            hostname="demo-ubuntu-server",
            mac_bytes=mac_to_bytes("02:00:00:00:00:05"),
            ip_bytes=ip_to_bytes("192.168.50.14"),
            ip_str="192.168.50.14",
            vendor="Canonical",
            device_type="server",
            os_family="Linux",
            model="MicroServer Gen10",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-ubuntu-server", "confidence": 0.95},
                {"source": "dhcp", "field": "os_family", "value": "Linux", "confidence": 0.92},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["plex", "docker-hub", "github", "cloudflare-dns", "ntp"],
            traffic_weight=1.4,
            active_hours=(0, 24),  # 24/7
        ),
        SyntheticDevice(
            id=6,
            name="Synology DiskStation",
            hostname="demo-synology-nas",
            mac_bytes=mac_to_bytes("02:00:00:00:00:06"),
            ip_bytes=ip_to_bytes("192.168.50.15"),
            ip_str="192.168.50.15",
            vendor="Synology",
            device_type="nas",
            os_family="DSM",
            model="DS923+",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-synology-nas", "confidence": 0.95},
                {"source": "mdns", "field": "model", "value": "DS923+", "confidence": 0.98},
                {"source": "upnp", "field": "vendor", "value": "Synology Inc.", "confidence": 0.95},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["synology-dsm", "nas-smb", "docker-hub", "ntp", "cloudflare-backup"],
            traffic_weight=1.3,
            active_hours=(0, 24),  # 24/7 (nightly backups)
        ),
        SyntheticDevice(
            id=7,
            name="Sony PlayStation 5",
            hostname="demo-ps5",
            mac_bytes=mac_to_bytes("02:00:00:00:00:07"),
            ip_bytes=ip_to_bytes("192.168.50.16"),
            ip_str="192.168.50.16",
            vendor="Sony",
            device_type="console",
            os_family="PlayStation",
            model="CFI-1200",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-ps5", "confidence": 0.95},
                {"source": "upnp", "field": "model", "value": "PlayStation 5", "confidence": 0.98},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["playstation-network", "youtube", "twitch"],
            traffic_weight=1.6,
            active_hours=(18, 24),
        ),
        SyntheticDevice(
            id=8,
            name="Nintendo Switch",
            hostname="demo-nintendo-switch",
            mac_bytes=mac_to_bytes("02:00:00:00:00:08"),
            ip_bytes=ip_to_bytes("192.168.50.17"),
            ip_str="192.168.50.17",
            vendor="Nintendo",
            device_type="console",
            os_family="Horizon",
            model="HAC-001(-01)",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-nintendo-switch", "confidence": 0.95},
                {"source": "oui", "field": "vendor", "value": "Nintendo Co., Ltd.", "confidence": 0.90},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["nintendo-eshop", "youtube"],
            traffic_weight=0.7,
            active_hours=(19, 23),
        ),
        SyntheticDevice(
            id=9,
            name="Apple TV 4K",
            hostname="demo-appletv",
            mac_bytes=mac_to_bytes("02:00:00:00:00:09"),
            ip_bytes=ip_to_bytes("192.168.50.18"),
            ip_str="192.168.50.18",
            vendor="Apple",
            device_type="tv",
            os_family="tvOS",
            model="AppleTV14,1",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-appletv", "confidence": 0.95},
                {"source": "mdns", "field": "model", "value": "AppleTV14,1", "confidence": 0.98},
                {"source": "mdns", "field": "os_family", "value": "tvOS", "confidence": 0.95},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["netflix", "youtube", "amazon-prime-video", "plex", "apple-music"],
            traffic_weight=2.0,
            active_hours=(19, 24),
        ),
        SyntheticDevice(
            id=10,
            name="HomePod mini",
            hostname="demo-homepod-mini",
            mac_bytes=mac_to_bytes("02:00:00:00:00:0A"),
            ip_bytes=ip_to_bytes("192.168.50.19"),
            ip_str="192.168.50.19",
            vendor="Apple",
            device_type="speaker",
            os_family="audioOS",
            model="AudioAccessory5,1",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-homepod-mini", "confidence": 0.95},
                {"source": "mdns", "field": "model", "value": "AudioAccessory5,1", "confidence": 0.98},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["apple-music", "icloud", "ntp"],
            traffic_weight=0.5,
            active_hours=(8, 23),
        ),
        SyntheticDevice(
            id=11,
            name="Aqara Smart Camera G3",
            hostname="demo-aqara-cam",
            mac_bytes=mac_to_bytes("02:00:00:00:00:0B"),
            ip_bytes=ip_to_bytes("192.168.50.20"),
            ip_str="192.168.50.20",
            vendor="Lumi",
            device_type="iot",
            os_family="Linux",
            model="Camera Hub G3",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-aqara-cam", "confidence": 0.90},
                {"source": "upnp", "field": "model", "value": "Camera Hub G3", "confidence": 0.92},
            ],
            first_seen_offset_hours=0.0,
            apps_affinity=["aqara-cloud", "nas-smb", "ntp"],
            traffic_weight=0.6,
            active_hours=(0, 24),
        ),
        # Device 12: Joined recently (e.g. 18 hours before end), triggers New Device Insight
        SyntheticDevice(
            id=12,
            name="Guest Steam Deck",
            hostname="demo-steam-deck",
            mac_bytes=mac_to_bytes("02:00:00:00:00:0C"),
            ip_bytes=ip_to_bytes("192.168.50.21"),
            ip_str="192.168.50.21",
            vendor="Valve",
            device_type="console",
            os_family="SteamOS",
            model="Jupiter",
            evidence_sources=[
                {"source": "dhcp", "field": "observation", "value": "demo-steam-deck", "confidence": 0.95},
                {"source": "dhcp", "field": "os_family", "value": "SteamOS", "confidence": 0.95},
            ],
            first_seen_offset_hours=30.0,  # Joined at hour 30 (within last 24 hours of a 48h span)
            apps_affinity=["steam", "discord", "youtube"],
            traffic_weight=1.4,
            active_hours=(14, 23),
        ),
    ]
    return devices


def create_synthetic_applications() -> Dict[str, SyntheticApp]:
    apps = [
        SyntheticApp(
            app_id="youtube",
            name="YouTube",
            category_id="video",
            organization_id="google",
            protocol=17,  # QUIC / UDP 443
            protocol_id="quic",
            domains=["youtube.com", "googlevideo.com", "ytimg.com"],
            remote_ips=["142.250.180.14", "142.250.185.206", "172.217.16.142", "142.251.46.174"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.02,
            bytes_range=(500_000, 15_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="netflix",
            name="Netflix",
            category_id="video",
            organization_id="netflix",
            protocol=6,  # TLS / TCP 443
            protocol_id="tls",
            domains=["netflix.com", "nflxvideo.net", "nflxext.com"],
            remote_ips=["198.38.118.140", "198.38.119.142", "45.57.94.138", "23.246.2.14"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.015,
            bytes_range=(2_000_000, 25_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="bilibili",
            name="Bilibili",
            category_id="video",
            organization_id="bilibili",
            protocol=6,
            protocol_id="tls",
            domains=["bilibili.com", "bilivideo.com", "hdslb.com"],
            remote_ips=["119.3.70.189", "120.92.153.22", "101.91.22.140", "47.100.121.55"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.02,
            bytes_range=(1_000_000, 18_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="github",
            name="GitHub",
            category_id="technology",
            organization_id="github",
            protocol=6,
            protocol_id="tls",
            domains=["github.com", "api.github.com", "raw.githubusercontent.com", "github.githubassets.com"],
            remote_ips=["140.82.112.4", "140.82.114.3", "140.82.121.4", "185.199.108.133"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.25,
            bytes_range=(50_000, 2_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="openai",
            name="OpenAI",
            category_id="technology",
            organization_id="openai",
            protocol=6,
            protocol_id="tls",
            domains=["api.openai.com", "chatgpt.com", "auth0.openai.com"],
            remote_ips=["104.18.32.47", "172.64.155.249", "104.18.33.47"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.15,
            bytes_range=(20_000, 800_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="steam",
            name="Steam",
            category_id="gaming",
            organization_id="valve",
            protocol=6,
            protocol_id="tls",
            domains=["steampowered.com", "steamcommunity.com", "steamcontent.com"],
            remote_ips=["162.254.192.40", "162.254.193.47", "155.133.246.30"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.03,
            bytes_range=(1_000_000, 35_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="playstation-network",
            name="PlayStation Network",
            category_id="gaming",
            organization_id="sony",
            protocol=6,
            protocol_id="tls",
            domains=["playstation.net", "sonyentertainmentnetwork.com"],
            remote_ips=["104.120.10.15", "23.208.188.10", "184.85.120.32"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.05,
            bytes_range=(800_000, 20_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="nintendo-eshop",
            name="Nintendo eShop",
            category_id="gaming",
            organization_id="nintendo",
            protocol=6,
            protocol_id="tls",
            domains=["nintendo.com", "nintendo.net"],
            remote_ips=["13.249.77.10", "13.249.77.45"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.04,
            bytes_range=(200_000, 8_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="spotify",
            name="Spotify",
            category_id="music",
            organization_id="spotify",
            protocol=6,
            protocol_id="tls",
            domains=["spotify.com", "audio-ak-spotify-com.akamaized.net", "spclient.wg.spotify.com"],
            remote_ips=["104.199.65.124", "35.186.224.25", "151.101.65.178"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.02,
            bytes_range=(300_000, 4_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="apple-music",
            name="Apple Music",
            category_id="music",
            organization_id="apple",
            protocol=6,
            protocol_id="tls",
            domains=["music.apple.com", "aod.itunes.apple.com"],
            remote_ips=["17.253.144.10", "17.253.81.205"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.02,
            bytes_range=(400_000, 5_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="icloud",
            name="Apple iCloud",
            category_id="cloud",
            organization_id="apple",
            protocol=6,
            protocol_id="tls",
            domains=["icloud.com", "gateway.icloud.com", "p53-content.icloud.com"],
            remote_ips=["17.248.190.252", "17.248.190.253"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.40,
            bytes_range=(100_000, 6_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="slack",
            name="Slack",
            category_id="communication",
            organization_id="salesforce",
            protocol=6,
            protocol_id="tls",
            domains=["slack.com", "app.slack.com", "edge.slack.com"],
            remote_ips=["44.234.190.10", "54.214.24.110"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.20,
            bytes_range=(50_000, 500_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="discord",
            name="Discord",
            category_id="communication",
            organization_id="discord",
            protocol=17,
            protocol_id="quic",
            domains=["discord.com", "gateway.discord.gg", "cdn.discordapp.com"],
            remote_ips=["162.159.130.233", "162.159.135.232"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.18,
            bytes_range=(100_000, 2_500_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="wechat",
            name="WeChat",
            category_id="social",
            organization_id="tencent",
            protocol=6,
            protocol_id="tls",
            domains=["weixin.qq.com", "short.weixin.qq.com"],
            remote_ips=["182.254.116.117", "101.226.90.166"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.12,
            bytes_range=(30_000, 1_200_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="telegram",
            name="Telegram",
            category_id="communication",
            organization_id="telegram",
            protocol=6,
            protocol_id="tls",
            domains=["telegram.org", "venus.web.telegram.org"],
            remote_ips=["149.154.167.99", "149.154.175.50"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.15,
            bytes_range=(20_000, 800_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="reddit",
            name="Reddit",
            category_id="social",
            organization_id="reddit",
            protocol=6,
            protocol_id="tls",
            domains=["reddit.com", "i.redd.it", "v.redd.it"],
            remote_ips=["151.101.1.140", "151.101.65.140", "151.101.129.140"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.08,
            bytes_range=(80_000, 2_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="microsoft-365",
            name="Microsoft 365",
            category_id="productivity",
            organization_id="microsoft",
            protocol=6,
            protocol_id="tls",
            domains=["office.com", "outlook.office.com", "sharepoint.com"],
            remote_ips=["52.96.166.130", "52.96.167.146", "40.97.128.210"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.20,
            bytes_range=(50_000, 1_500_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="notion",
            name="Notion",
            category_id="productivity",
            organization_id="notion",
            protocol=6,
            protocol_id="tls",
            domains=["notion.so", "msgstore.www.notion.so"],
            remote_ips=["104.18.23.102", "104.18.22.102"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.15,
            bytes_range=(30_000, 800_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="amazon-prime-video",
            name="Amazon Prime Video",
            category_id="video",
            organization_id="amazon",
            protocol=6,
            protocol_id="tls",
            domains=["primevideo.com", "atv-ps.amazon.com"],
            remote_ips=["54.239.30.12", "54.239.31.8"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.015,
            bytes_range=(2_000_000, 20_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="docker-hub",
            name="Docker Hub",
            category_id="technology",
            organization_id="docker",
            protocol=6,
            protocol_id="tls",
            domains=["registry-1.docker.io", "hub.docker.com"],
            remote_ips=["52.200.132.180", "54.198.86.111"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.10,
            bytes_range=(200_000, 15_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="wikipedia",
            name="Wikipedia",
            category_id="education",
            organization_id="wikimedia",
            protocol=6,
            protocol_id="tls",
            domains=["wikipedia.org", "en.wikipedia.org", "upload.wikimedia.org"],
            remote_ips=["185.15.59.224", "185.15.58.224"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.05,
            bytes_range=(20_000, 400_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="cloudflare-dns",
            name="Cloudflare DNS",
            category_id="infrastructure",
            organization_id="cloudflare",
            protocol=17,
            protocol_id="dns",
            domains=["one.one.one.one", "cloudflare-dns.com"],
            remote_ips=["1.1.1.1", "1.0.0.1"],
            default_port=53,
            traffic_role="client",
            base_upload_ratio=0.45,
            bytes_range=(2_000, 25_000),
            classification_reason="port_match",
        ),
        SyntheticApp(
            app_id="google-dns",
            name="Google DNS",
            category_id="infrastructure",
            organization_id="google",
            protocol=17,
            protocol_id="dns",
            domains=["dns.google"],
            remote_ips=["8.8.8.8", "8.8.4.4"],
            default_port=53,
            traffic_role="client",
            base_upload_ratio=0.45,
            bytes_range=(2_000, 25_000),
            classification_reason="port_match",
        ),
        SyntheticApp(
            app_id="ntp",
            name="NTP Service",
            category_id="infrastructure",
            organization_id="cloudflare",
            protocol=17,
            protocol_id="ntp",
            domains=["time.cloudflare.com"],
            remote_ips=["162.159.200.1", "162.159.200.123"],
            default_port=123,
            traffic_role="client",
            base_upload_ratio=0.50,
            bytes_range=(500, 5_000),
            classification_reason="port_match",
        ),
        SyntheticApp(
            app_id="twitch",
            name="Twitch",
            category_id="video",
            organization_id="amazon",
            protocol=6,
            protocol_id="tls",
            domains=["twitch.tv", "video-edge.twitch.tv"],
            remote_ips=["151.101.2.167", "151.101.66.167"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.02,
            bytes_range=(1_500_000, 16_000_000),
            classification_reason="sni",
        ),
        SyntheticApp(
            app_id="aqara-cloud",
            name="Aqara IoT Cloud",
            category_id="iot",
            organization_id="lumi",
            protocol=6,
            protocol_id="tls",
            domains=["aiot-open-usa.aqara.com"],
            remote_ips=["47.254.88.12", "47.254.89.20"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.35,
            bytes_range=(5_000, 80_000),
            classification_reason="sni",
        ),
        # High upload test application (cloud backup), triggers High Upload Insight
        SyntheticApp(
            app_id="cloudflare-backup",
            name="Offsite R2 Backup",
            category_id="cloud",
            organization_id="cloudflare",
            protocol=6,
            protocol_id="tls",
            domains=["r2.cloudflarestorage.com"],
            remote_ips=["104.18.0.40"],
            default_port=443,
            traffic_role="client",
            base_upload_ratio=0.98,
            bytes_range=(15_000_000, 60_000_000),
            classification_reason="sni",
        ),
        # Internal LAN applications
        SyntheticApp(
            app_id="nas-smb",
            name="LAN File Sharing (SMB)",
            category_id="file_sharing",
            organization_id="local",
            protocol=6,
            protocol_id="smb",
            domains=["synology.lan"],
            remote_ips=["192.168.50.15"],  # NAS LAN IP
            default_port=445,
            traffic_role="client",
            base_upload_ratio=0.40,
            bytes_range=(1_000_000, 20_000_000),
            classification_reason="port_match",
        ),
        SyntheticApp(
            app_id="plex",
            name="Plex Media Server",
            category_id="video",
            organization_id="local",
            protocol=6,
            protocol_id="http",
            domains=["plex.lan"],
            remote_ips=["192.168.50.14"],  # Home Server LAN IP
            default_port=32400,
            traffic_role="server",
            base_upload_ratio=0.03,
            bytes_range=(2_000_000, 28_000_000),
            classification_reason="port_match",
        ),
        SyntheticApp(
            app_id="synology-dsm",
            name="Synology DSM Portal",
            category_id="management",
            organization_id="local",
            protocol=6,
            protocol_id="tls",
            domains=["dsm.lan"],
            remote_ips=["192.168.50.15"],  # NAS LAN IP
            default_port=5001,
            traffic_role="server",
            base_upload_ratio=0.20,
            bytes_range=(50_000, 800_000),
            classification_reason="port_match",
        ),
    ]
    return {app.app_id: app for app in apps}


def apply_migrations(conn: sqlite3.Connection, repo_root: Path, verbose: bool = False) -> None:
    """Read migrations directly from migrations/sqlite/*.sql and apply them."""
    migrations_dir = Path(
        os.environ.get("NETQMON_MIGRATIONS_DIR", repo_root / "migrations" / "sqlite")
    )
    if not migrations_dir.exists():
        raise FileNotFoundError(f"Migrations directory not found: {migrations_dir}")

    migration_files = sorted(migrations_dir.glob("*.sql"))
    if not migration_files:
        raise FileNotFoundError(f"No .sql migration files found in {migrations_dir}")

    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );
        """
    )
    conn.commit()

    for idx, fpath in enumerate(migration_files, start=1):
        if verbose:
            print(f"[INFO] Applying migration {idx}: {fpath.name}")
        sql_script = fpath.read_text(encoding="utf-8")
        cur.executescript(sql_script)
        cur.execute(
            "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (?, ?);",
            (idx, TARGET_MAX_TIMESTAMP_MS),
        )
        conn.commit()


def calculate_diurnal_multiplier(hour_float: float) -> float:
    """
    Returns traffic volume multiplier based on time of day (0.0 to 24.0).
    - 01:00-06:00: Night low (0.08 - 0.15)
    - 06:00-09:00: Morning rise (0.2 -> 0.7)
    - 09:00-18:00: Work day (0.7 -> 0.95)
    - 18:00-23:00: Peak entertainment (1.2 -> 1.85)
    - 23:00-01:00: Night descent (1.0 -> 0.2)
    """
    h = hour_float % 24.0
    if 1.0 <= h < 6.0:
        return 0.08 + 0.04 * math.sin((h - 1.0) * math.pi / 5.0)
    elif 6.0 <= h < 9.0:
        prog = (h - 6.0) / 3.0
        return 0.12 + prog * 0.58
    elif 9.0 <= h < 18.0:
        prog = (h - 9.0) / 9.0
        lunch_bump = 0.25 * math.sin(prog * math.pi)
        return 0.70 + lunch_bump
    elif 18.0 <= h < 23.0:
        prog = (h - 18.0) / 5.0
        peak = 0.65 * math.sin(prog * math.pi)
        return 1.20 + peak
    else:  # 23.0 to 24.0 or 0.0 to 1.0
        dist = (h - 23.0) if h >= 23.0 else (h + 1.0)
        return max(0.10, 1.0 - (dist / 2.0) * 0.85)


def generate_database(
    output_path: str,
    seed: int = 20260921,
    hours: int = 48,
    force: bool = False,
    verbose: bool = False,
    now: bool = False,
) -> None:
    random.seed(seed)
    out_file = Path(output_path).resolve()
    if out_file.exists():
        if not force:
            print(f"[ERROR] Output database {out_file} already exists. Use --force to overwrite.", file=sys.stderr)
            sys.exit(1)
        out_file.unlink()

    repo_root = Path(__file__).resolve().parent.parent.parent
    if verbose:
        print(f"[INFO] Using repository root: {repo_root}")
        print(f"[INFO] Initializing SQLite template database (seed={seed}, hours={hours}, now={now})...")

    # Work in a memory database first for speed, then VACUUM INTO destination file
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    # 1. Apply real schema migrations
    apply_migrations(conn, repo_root, verbose=verbose)

    if now:
        now_ms = int(time.time() * 1000)
        end_time_ms = ((now_ms - 30_000) // 60_000) * 60_000
    else:
        end_time_ms = TARGET_MAX_TIMESTAMP_MS
    start_time_ms = end_time_ms - (hours * 3600 * 1000)

    # 2. Populate Site & Gateway
    cur.execute("INSERT OR IGNORE INTO sites(id, name, created_at) VALUES ('default', 'Demo Site', ?);", (start_time_ms,))
    cur.execute(
        """
        INSERT INTO gateways(
            id, site_id, name, agent_token_hash, agent_version,
            arch, kernel_version, openwrt_version, status, last_seen, created_at
        ) VALUES (?, 'default', ?, ?, 'v0.1.0', 'x86_64', 'Linux 6.6.0', 'OpenWrt 23.05.3', 'online', ?, ?);
        """,
        (DEMO_GATEWAY_ID, DEMO_GATEWAY_NAME, DEMO_GATEWAY_TOKEN_HASH, end_time_ms, start_time_ms),
    )

    # 3. Setup Devices & Device Addresses & Evidence
    devices = create_synthetic_devices(start_time_ms, end_time_ms)
    app_catalog = create_synthetic_applications()

    if verbose:
        print(f"[INFO] Populating {len(devices)} synthetic devices...")

    for dev in devices:
        dev_first_seen = start_time_ms + int(dev.first_seen_offset_hours * 3600 * 1000)
        dev_last_seen = end_time_ms

        evidence_json_list = []
        for ev in dev.evidence_sources:
            ev_record = {
                "source": ev["source"],
                "field": ev["field"],
                "value": ev["value"],
                "confidence": ev["confidence"],
                "first_seen": dev_first_seen,
                "last_seen": dev_last_seen,
                "hit_count": random.randint(15, 120),
                "metadata_json": json.dumps({"source_agent": DEMO_GATEWAY_ID, "inferred": True}),
            }
            evidence_json_list.append(ev_record)
            cur.execute(
                """
                INSERT INTO device_evidence(
                    gateway_id, mac, source, field, value, confidence,
                    first_seen, last_seen, hit_count, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    DEMO_GATEWAY_ID,
                    dev.mac_bytes,
                    ev["source"],
                    ev["field"],
                    ev["value"],
                    ev["confidence"],
                    dev_first_seen,
                    dev_last_seen,
                    ev_record["hit_count"],
                    ev_record["metadata_json"],
                ),
            )

        identity_evidence_json = json.dumps(evidence_json_list)
        cur.execute(
            """
            INSERT INTO devices(
                id, gateway_id, mac, hostname, display_name, vendor,
                device_type, os_family, model, identity_confidence,
                identity_evidence_json, vendor_confidence, device_type_confidence,
                os_confidence, model_confidence, private_mac, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'high', ?, 0.95, 0.92, 0.94, 0.90, 0, ?, ?);
            """,
            (
                dev.id,
                DEMO_GATEWAY_ID,
                dev.mac_bytes,
                dev.hostname,
                dev.name,
                dev.vendor,
                dev.device_type,
                dev.os_family,
                dev.model,
                identity_evidence_json,
                dev_first_seen,
                dev_last_seen,
            ),
        )

        # Device Address
        self_host_app = None
        self_host_conf = 0.0
        self_host_src = None
        if dev.name == "Synology DiskStation":
            self_host_app = "synology-dsm"
            self_host_conf = 0.98
            self_host_src = "http"
        elif dev.name == "Ubuntu Home Server":
            self_host_app = "plex"
            self_host_conf = 0.95
            self_host_src = "mdns"

        cur.execute(
            """
            INSERT INTO device_addresses(
                device_id, ip, ip_version, first_seen, last_seen,
                application_id, application_confidence, application_source, application_last_seen
            ) VALUES (?, ?, 4, ?, ?, ?, ?, ?, ?);
            """,
            (
                dev.id,
                dev.ip_bytes,
                dev_first_seen,
                dev_last_seen,
                self_host_app,
                self_host_conf,
                self_host_src,
                dev_last_seen if self_host_app else None,
            ),
        )

    # 4. Populate self_host_endpoint_evidence
    cur.execute(
        """
        INSERT INTO self_host_endpoint_evidence(
            gateway_id, ip, protocol, port, application_id,
            confidence, source, last_seen, expires_at
        ) VALUES
        (?, ?, 6, 5001, 'synology-dsm', 0.98, 'port_scan', ?, ?),
        (?, ?, 6, 32400, 'plex', 0.95, 'ssdp', ?, ?);
        """,
        (
            DEMO_GATEWAY_ID,
            ip_to_bytes("192.168.50.15"),
            end_time_ms,
            end_time_ms + 7 * 86400 * 1000,
            DEMO_GATEWAY_ID,
            ip_to_bytes("192.168.50.14"),
            end_time_ms,
            end_time_ms + 7 * 86400 * 1000,
        ),
    )

    # 5. Minute Traffic & Flow Sessions Generation
    total_minutes = hours * 60
    if verbose:
        print(f"[INFO] Generating minute traffic and flows across {total_minutes} minute intervals...")

    flow_sessions_dict: Dict[str, Dict[str, Any]] = {}

    total_min_dict: Dict[int, List[int]] = {}
    dev_min_dict: Dict[Tuple[int, int], List[int]] = {}
    app_min_dict: Dict[Tuple[int, str, str], List[int]] = {}
    dom_min_dict: Dict[Tuple[int, str], List[int]] = {}
    dst_min_dict: Dict[Tuple[int, bytes], List[int]] = {}
    scope_min_dict: Dict[Tuple, List[int]] = {}

    client_port_counter: Dict[int, int] = {dev.id: 49152 + (dev.id * 1000) for dev in devices}

    for minute_idx in range(total_minutes):
        current_minute_ts = start_time_ms + (minute_idx * 60_000)
        hour_of_day = (current_minute_ts // 3600_000) % 24
        minute_of_hour = (current_minute_ts // 60_000) % 60
        hour_float = hour_of_day + (minute_of_hour / 60.0)

        diurnal = calculate_diurnal_multiplier(hour_float)

        for dev in devices:
            dev_first_seen = start_time_ms + int(dev.first_seen_offset_hours * 3600 * 1000)
            if current_minute_ts < dev_first_seen:
                continue

            start_h, end_h = dev.active_hours
            if start_h < end_h:
                is_active_hour = (start_h <= hour_of_day < end_h)
            else:
                is_active_hour = (hour_of_day >= start_h or hour_of_day < end_h)

            prob = (0.75 if is_active_hour else 0.10) * dev.traffic_weight * diurnal
            prob = max(0.05, min(0.98, prob))

            if random.random() > prob:
                continue

            num_apps = random.choices([1, 2, 3], weights=[0.6, 0.3, 0.1])[0]
            chosen_app_ids = random.sample(dev.apps_affinity, min(num_apps, len(dev.apps_affinity)))

            for app_id in chosen_app_ids:
                app = app_catalog.get(app_id)
                if not app:
                    continue

                min_b, max_b = app.bytes_range
                burst = math.exp(random.gauss(0.0, 0.35))
                raw_bytes = int(random.uniform(min_b, max_b) * diurnal * burst)
                raw_bytes = max(1000, raw_bytes)

                upload_ratio = app.base_upload_ratio * random.uniform(0.8, 1.2)
                upload_ratio = max(0.005, min(0.995, upload_ratio))
                up_bytes = int(raw_bytes * upload_ratio)
                down_bytes = raw_bytes - up_bytes

                pkts = max(2, (up_bytes + down_bytes) // random.randint(1100, 1400))
                flow_inc = 1

                domain = random.choice(app.domains)
                remote_ip_str = random.choice(app.remote_ips)
                remote_ip_b = ip_to_bytes(remote_ip_str)

                is_local = remote_ip_str.startswith("192.168.50.")
                if is_local:
                    scope = 2  # FLOW_SCOPE_INTERNAL
                    path_type = 2  # PATH_TYPE_INTERNAL
                    nat = 1  # NAT_TYPE_NONE
                    src_seg = "lan"
                    dst_seg = "lan"
                else:
                    scope = 1  # FLOW_SCOPE_INTERNET
                    path_type = 1  # PATH_TYPE_FORWARDED
                    nat = 2  # NAT_TYPE_SNAT
                    src_seg = "lan"
                    dst_seg = "wan"

                client_port_counter[dev.id] += 1
                if client_port_counter[dev.id] > 64000:
                    client_port_counter[dev.id] = 49152 + (dev.id * 1000)
                client_port = client_port_counter[dev.id]

                flow_id = format_flow_id(
                    DEMO_GATEWAY_ID,
                    4,
                    app.protocol,
                    dev.ip_bytes,
                    client_port,
                    remote_ip_b,
                    app.default_port,
                    1,
                )

                duration_ms = random.randint(15_000, 240_000)
                started_at = max(dev_first_seen, current_minute_ts - duration_ms)
                last_seen_at = current_minute_ts
                is_ended = (random.random() < 0.85)
                ended_at = (last_seen_at + random.randint(1000, 5000)) if is_ended else None
                checkpointed_at = last_seen_at

                flow_sessions_dict[flow_id] = {
                    "id": flow_id,
                    "gateway_id": DEMO_GATEWAY_ID,
                    "device_id": dev.id,
                    "ip_version": 4,
                    "protocol": app.protocol,
                    "client_ip": dev.ip_bytes,
                    "client_port": client_port,
                    "remote_ip": remote_ip_b,
                    "remote_port": app.default_port,
                    "direction": 1,
                    "domain": domain,
                    "application_id": app.app_id,
                    "category_id": app.category_id,
                    "traffic_role": app.traffic_role,
                    "protocol_id": app.protocol_id,
                    "organization_id": app.organization_id,
                    "organization_confidence": 0.95,
                    "application_confidence": 0.92,
                    "protocol_confidence": 0.90,
                    "classification_confidence": 0.93,
                    "classification_reason": app.classification_reason,
                    "classification_evidence_json": "[]",
                    "upload_bytes": up_bytes,
                    "download_bytes": down_bytes,
                    "packets": pkts,
                    "started_at": started_at,
                    "last_seen_at": last_seen_at,
                    "ended_at": ended_at,
                    "checkpointed_at": checkpointed_at,
                    "scope": scope,
                    "path_type": path_type,
                    "nat": nat,
                    "source_segment": src_seg,
                    "destination_segment": dst_seg,
                }

                # 1. Total
                tot = total_min_dict.setdefault(current_minute_ts, [0, 0, 0, 0])
                tot[0] += up_bytes
                tot[1] += down_bytes
                tot[2] += pkts
                tot[3] += flow_inc

                # 2. Device
                dev_k = (current_minute_ts, dev.id)
                dm = dev_min_dict.setdefault(dev_k, [0, 0, 0, 0])
                dm[0] += up_bytes
                dm[1] += down_bytes
                dm[2] += pkts
                dm[3] += flow_inc

                # 3. Application
                app_k = (current_minute_ts, app.app_id, app.category_id)
                am = app_min_dict.setdefault(app_k, [0, 0, 0, 0])
                am[0] += up_bytes
                am[1] += down_bytes
                am[2] += pkts
                am[3] += flow_inc

                # 4. Domain
                dom_k = (current_minute_ts, domain)
                dom_m = dom_min_dict.setdefault(dom_k, [0, 0, 0, 0])
                dom_m[0] += up_bytes
                dom_m[1] += down_bytes
                dom_m[2] += pkts
                dom_m[3] += flow_inc

                # 5. Destination
                dst_k = (current_minute_ts, remote_ip_b)
                dst_m = dst_min_dict.setdefault(dst_k, [0, 0, 0, 0])
                dst_m[0] += up_bytes
                dst_m[1] += down_bytes
                dst_m[2] += pkts
                dst_m[3] += flow_inc

                # 6. Scope (v2 with protocol & protocol_id)
                scope_k = (
                    current_minute_ts,
                    scope,
                    1,
                    dev.id,
                    app.app_id,
                    app.category_id,
                    domain,
                    remote_ip_b,
                    app.protocol,
                    app.protocol_id,
                )
                sm = scope_min_dict.setdefault(scope_k, [0, 0, 0, 0])
                sm[0] += up_bytes
                sm[1] += down_bytes
                sm[2] += pkts
                sm[3] += flow_inc

    # 6. Insert flow_sessions
    if verbose:
        print(f"[INFO] Inserting {len(flow_sessions_dict)} flow sessions...")

    cur.executemany(
        """
        INSERT INTO flow_sessions(
            id, gateway_id, device_id, ip_version, protocol, client_ip, client_port,
            remote_ip, remote_port, direction, domain, application_id, category_id,
            traffic_role, protocol_id, organization_id, organization_confidence,
            application_confidence, protocol_confidence, classification_confidence,
            classification_reason, classification_evidence_json, upload_bytes,
            download_bytes, packets, started_at, last_seen_at, ended_at,
            checkpointed_at, scope, path_type, nat, source_segment, destination_segment
        ) VALUES (
            :id, :gateway_id, :device_id, :ip_version, :protocol, :client_ip, :client_port,
            :remote_ip, :remote_port, :direction, :domain, :application_id, :category_id,
            :traffic_role, :protocol_id, :organization_id, :organization_confidence,
            :application_confidence, :protocol_confidence, :classification_confidence,
            :classification_reason, :classification_evidence_json, :upload_bytes,
            :download_bytes, :packets, :started_at, :last_seen_at, :ended_at,
            :checkpointed_at, :scope, :path_type, :nat, :source_segment, :destination_segment
        );
        """,
        list(flow_sessions_dict.values()),
    )
    conn.commit()

    # 7. Insert Minute Rollups
    if verbose:
        print(f"[INFO] Inserting traffic_total_minute ({len(total_min_dict)} rows)...")
    cur.executemany(
        """
        INSERT INTO traffic_total_minute(timestamp, gateway_id, upload_bytes, download_bytes, packets, flow_count)
        VALUES (?, 'demo-gateway', ?, ?, ?, ?);
        """,
        [(ts, vals[0], vals[1], vals[2], vals[3]) for ts, vals in total_min_dict.items()],
    )

    if verbose:
        print(f"[INFO] Inserting traffic_device_minute ({len(dev_min_dict)} rows)...")
    cur.executemany(
        """
        INSERT INTO traffic_device_minute(timestamp, gateway_id, device_id, upload_bytes, download_bytes, packets, flow_count)
        VALUES (?, 'demo-gateway', ?, ?, ?, ?, ?);
        """,
        [(ts, dev_id, vals[0], vals[1], vals[2], vals[3]) for (ts, dev_id), vals in dev_min_dict.items()],
    )

    if verbose:
        print(f"[INFO] Inserting traffic_application_minute ({len(app_min_dict)} rows)...")
    cur.executemany(
        """
        INSERT INTO traffic_application_minute(timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
        VALUES (?, 'demo-gateway', ?, ?, ?, ?, ?, ?);
        """,
        [(ts, app_id, cat_id, vals[0], vals[1], vals[2], vals[3]) for (ts, app_id, cat_id), vals in app_min_dict.items()],
    )

    if verbose:
        print(f"[INFO] Inserting traffic_domain_minute ({len(dom_min_dict)} rows)...")
    cur.executemany(
        """
        INSERT INTO traffic_domain_minute(timestamp, gateway_id, domain, upload_bytes, download_bytes, packets, flow_count)
        VALUES (?, 'demo-gateway', ?, ?, ?, ?, ?);
        """,
        [(ts, dom, vals[0], vals[1], vals[2], vals[3]) for (ts, dom), vals in dom_min_dict.items()],
    )

    if verbose:
        print(f"[INFO] Inserting traffic_destination_minute ({len(dst_min_dict)} rows)...")
    cur.executemany(
        """
        INSERT INTO traffic_destination_minute(timestamp, gateway_id, remote_ip, upload_bytes, download_bytes, packets, flow_count)
        VALUES (?, 'demo-gateway', ?, ?, ?, ?, ?);
        """,
        [(ts, rip, vals[0], vals[1], vals[2], vals[3]) for (ts, rip), vals in dst_min_dict.items()],
    )

    if verbose:
        print(f"[INFO] Inserting traffic_scope_minute ({len(scope_min_dict)} rows)...")
    cur.executemany(
        """
        INSERT INTO traffic_scope_minute(
            timestamp, gateway_id, scope, direction, device_id,
            application_id, category_id, domain, remote_ip, protocol, protocol_id,
            upload_bytes, download_bytes, packets, flow_count
        ) VALUES (?, 'demo-gateway', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        [
            (
                k[0],
                k[1],
                k[2],
                k[3],
                k[4],
                k[5],
                k[6],
                k[7],
                k[8],
                k[9],
                vals[0],
                vals[1],
                vals[2],
                vals[3],
            )
            for k, vals in scope_min_dict.items()
        ],
    )
    conn.commit()

    # 8. Aggregate Hour & Day Rollups in SQL
    if verbose:
        print("[INFO] Aggregating hourly and daily traffic rollups...")

    # traffic_total_hour / day
    cur.execute(
        """
        INSERT INTO traffic_total_hour(timestamp, gateway_id, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 3600000) * 3600000 AS ts, gateway_id,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_total_minute
        GROUP BY ts, gateway_id;
        """
    )
    cur.execute(
        """
        INSERT INTO traffic_total_day(timestamp, gateway_id, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 86400000) * 86400000 AS ts, gateway_id,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_total_hour
        GROUP BY ts, gateway_id;
        """
    )

    # traffic_device_hour / day
    cur.execute(
        """
        INSERT INTO traffic_device_hour(timestamp, gateway_id, device_id, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 3600000) * 3600000 AS ts, gateway_id, device_id,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_device_minute
        GROUP BY ts, gateway_id, device_id;
        """
    )
    cur.execute(
        """
        INSERT INTO traffic_device_day(timestamp, gateway_id, device_id, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 86400000) * 86400000 AS ts, gateway_id, device_id,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_device_hour
        GROUP BY ts, gateway_id, device_id;
        """
    )

    # traffic_application_hour / day
    cur.execute(
        """
        INSERT INTO traffic_application_hour(timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 3600000) * 3600000 AS ts, gateway_id, application_id, category_id,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_application_minute
        GROUP BY ts, gateway_id, application_id, category_id;
        """
    )
    cur.execute(
        """
        INSERT INTO traffic_application_day(timestamp, gateway_id, application_id, category_id, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 86400000) * 86400000 AS ts, gateway_id, application_id, category_id,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_application_hour
        GROUP BY ts, gateway_id, application_id, category_id;
        """
    )

    # traffic_domain_hour / day
    cur.execute(
        """
        INSERT INTO traffic_domain_hour(timestamp, gateway_id, domain, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 3600000) * 3600000 AS ts, gateway_id, domain,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_domain_minute
        GROUP BY ts, gateway_id, domain;
        """
    )
    cur.execute(
        """
        INSERT INTO traffic_domain_day(timestamp, gateway_id, domain, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 86400000) * 86400000 AS ts, gateway_id, domain,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_domain_hour
        GROUP BY ts, gateway_id, domain;
        """
    )

    # traffic_destination_hour / day
    cur.execute(
        """
        INSERT INTO traffic_destination_hour(timestamp, gateway_id, remote_ip, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 3600000) * 3600000 AS ts, gateway_id, remote_ip,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_destination_minute
        GROUP BY ts, gateway_id, remote_ip;
        """
    )
    cur.execute(
        """
        INSERT INTO traffic_destination_day(timestamp, gateway_id, remote_ip, upload_bytes, download_bytes, packets, flow_count)
        SELECT (timestamp / 86400000) * 86400000 AS ts, gateway_id, remote_ip,
               SUM(upload_bytes), SUM(download_bytes), SUM(packets), SUM(flow_count)
        FROM traffic_destination_hour
        GROUP BY ts, gateway_id, remote_ip;
        """
    )
    conn.commit()

    # 9. Verify sensitive tables are strictly empty
    for tbl in ["users", "auth_sessions", "ingest_batches", "settings"]:
        cur.execute(f"SELECT COUNT(*) FROM {tbl};")
        cnt = cur.fetchone()[0]
        if cnt != 0:
            raise RuntimeError(f"Sanity check failed: table {tbl} is not empty (count={cnt})")

    # 10. Integrity check in-memory
    cur.execute("PRAGMA integrity_check;")
    chk = cur.fetchone()[0]
    if chk != "ok":
        raise RuntimeError(f"In-memory PRAGMA integrity_check failed: {chk}")

    cur.execute("PRAGMA foreign_key_check;")
    fks = cur.fetchall()
    if fks:
        raise RuntimeError(f"In-memory PRAGMA foreign_key_check failed: {fks}")

    # 11. Export clean database via VACUUM INTO
    if verbose:
        print(f"[INFO] Exporting pristine database via VACUUM INTO {out_file}...")

    safe_out_path = str(out_file).replace("'", "''")
    cur.execute(f"VACUUM INTO '{safe_out_path}';")
    conn.close()

    # 12. Final check on exported file
    file_size_bytes = out_file.stat().st_size
    file_size_mb = file_size_bytes / (1024 * 1024)
    print(f"[SUCCESS] Synthetic demo template database created: {out_file} ({file_size_mb:.2f} MB)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate 100% Synthetic Netqmon Demo SQLite Database.")
    parser.add_argument(
        "--output",
        default="netqmon-demo-template.db",
        help="Path to output demo template SQLite database (default: netqmon-demo-template.db)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20260921,
        help="Deterministic random seed (default: 20260921)",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=48,
        help="Historical duration in hours to generate (default: 48)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it already exists",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verbose generation details",
    )
    parser.add_argument(
        "--now",
        action="store_true",
        help="Align synthetic timestamps to current time (now - 30s)",
    )

    args = parser.parse_args()
    generate_database(
        output_path=args.output,
        seed=args.seed,
        hours=args.hours,
        force=args.force,
        verbose=args.verbose,
        now=args.now,
    )


if __name__ == "__main__":
    main()
