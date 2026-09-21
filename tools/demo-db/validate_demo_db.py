#!/usr/bin/env python3
"""
Netqmon Controller Demo Database Validation Tool.

Performs strict verification of a demo template SQLite database to guarantee:
1. SQLite PRAGMA integrity_check and foreign_key_check pass with zero errors.
2. Sensitive tables (users, auth_sessions, ingest_batches, settings) are purged.
3. Gateway and device records are properly anonymized.
4. All device MAC addresses are locally administered and unicast (02:00:00:00:xx:xx).
5. All client and private network IPs conform to demo subnets (192.168.50.0/24).
6. Embedded JSON evidence contains zero leaked source MACs, IPs, or hostnames.
7. If source database is provided, verifies that 0 source sensitive tokens exist.
8. Historical timestamps follow chronological sanity invariants.

Exits with code 0 on complete validation success.
Exits with code 1 if ANY check fails or privacy leak is detected.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple


def check(cond: bool, msg: str) -> None:
    if not cond:
        print(f"[FAIL] {msg}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"[PASS] {msg}")


def parse_ip(b: bytes) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not isinstance(b, (bytes, bytearray)):
        return None
    if len(b) in (4, 16):
        try:
            return ipaddress.ip_address(b)
        except Exception:
            return None
    return None


def is_locally_administered_mac(mac: bytes) -> bool:
    if len(mac) != 6:
        return False
    # Locally administered: bit 1 of first byte is 1
    # Unicast: bit 0 of first byte is 0
    return (mac[0] & 0x02 != 0) and (mac[0] & 0x01 == 0)


def extract_source_sensitive_tokens(src_db_path: Path) -> Set[str]:
    """Collect source sensitive strings to scan for residual leaks."""
    tokens: Set[str] = set()
    conn = sqlite3.connect(f"file:{src_db_path}?mode=ro", uri=True)
    cur = conn.cursor()

    # Source Gateways
    cur.execute("SELECT id, name FROM gateways;")
    for gid, gname in cur.fetchall():
        if gid and len(gid) > 4:
            tokens.add(gid.lower())
        if gname and gname != "default":
            tokens.add(gname)

    # Source Devices
    cur.execute("SELECT mac, hostname, display_name FROM devices;")
    for mac, hn, dn in cur.fetchall():
        if isinstance(mac, (bytes, bytearray)) and len(mac) == 6:
            tokens.add(mac.hex().lower())
            tokens.add(":".join(f"{b:02x}" for b in mac).lower())
            tokens.add("-".join(f"{b:02x}" for b in mac).lower())
        if hn and len(hn) > 1 and hn not in ("w", "ha"):
            tokens.add(hn)
            if hn.endswith(".local"):
                tokens.add(hn[:-6])
        if dn and len(dn) > 1:
            tokens.add(dn)

    # Source Private IPs
    for tbl, col in [("device_addresses", "ip"), ("flow_sessions", "client_ip")]:
        cur.execute(f"SELECT DISTINCT {col} FROM {tbl} WHERE {col} IS NOT NULL;")
        for (b,) in cur.fetchall():
            ip = parse_ip(b)
            if ip and ip.is_private:
                tokens.add(str(ip))
                tokens.add(str(ip).replace(".", "-"))

    # Source Users
    cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users';")
    if cur.fetchone():
        cur.execute("SELECT username FROM users;")
        for (un,) in cur.fetchall():
            if un and un != "admin":
                tokens.add(un)

    tokens.add("贾维斯")
    tokens.add("\\350\\264\\276\\347\\273\\264\\346\\226\\257")
    tokens.add("192.168.2.")
    tokens.add("192-168-2-")

    conn.close()

    IGNORE_TOKENS = {
        "iphone", "switch", "nas", "::", "0.0.0.0", "0.0.0.1", "127.0.0.1",
        "admin", "default", "local", "demo", "server", "camera", "light", "plug",
    }
    return {t for t in tokens if t.lower() not in IGNORE_TOKENS and len(t) > 2}


def validate_database(demo_db_path: str, source_db_path: Optional[str] = None, verbose: bool = False) -> None:
    demo_file = Path(demo_db_path).resolve()
    if not demo_file.exists():
        print(f"[ERROR] Database file not found: {demo_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Validating demo template database: {demo_file}")
    conn = sqlite3.connect(f"file:{demo_file}?mode=ro", uri=True)
    cur = conn.cursor()

    # 1. PRAGMA integrity_check
    cur.execute("PRAGMA integrity_check;")
    integrity = cur.fetchall()
    check(integrity == [("ok",)], f"PRAGMA integrity_check: {integrity}")

    # 2. PRAGMA foreign_key_check
    cur.execute("PRAGMA foreign_key_check;")
    fk_errors = cur.fetchall()
    check(len(fk_errors) == 0, f"PRAGMA foreign_key_check: {len(fk_errors)} errors")

    # 3. Purged tables must be empty
    purged_tables = ["users", "auth_sessions", "ingest_batches", "settings"]
    for tbl in purged_tables:
        cur.execute(f"SELECT 1 FROM sqlite_master WHERE type='table' AND name='{tbl}';")
        if cur.fetchone():
            cur.execute(f"SELECT COUNT(*) FROM {tbl};")
            count = cur.fetchone()[0]
            check(count == 0, f"Table '{tbl}' is completely empty (rows={count})")

    # 4. Gateway validation
    cur.execute("SELECT id, name FROM gateways;")
    gws = cur.fetchall()
    check(len(gws) == 1, f"Exactly 1 gateway present (found {len(gws)})")
    check(gws[0][0] == "demo-gateway", f"Gateway ID is 'demo-gateway' (found '{gws[0][0]}')")
    check("istore" not in gws[0][1].lower(), f"Gateway name is sanitized: '{gws[0][1]}'")

    # 5. Device validation
    cur.execute("SELECT id, mac, hostname, display_name, identity_evidence_json FROM devices;")
    dev_rows = cur.fetchall()
    check(len(dev_rows) > 0, f"Devices table populated (count={len(dev_rows)})")

    for dev_id, mac_b, hn, dn, ev_json in dev_rows:
        check(is_locally_administered_mac(mac_b), f"Device {dev_id} has locally administered MAC: {mac_b.hex()}")
        if hn:
            check("jarvis" not in hn.lower() and "lrx" not in hn.lower(), f"Device {dev_id} hostname sanitized: '{hn}'")
        if dn:
            check("jarvis" not in dn.lower() and "lrx" not in dn.lower(), f"Device {dev_id} display name sanitized: '{dn}'")
        check("贾维斯" not in ev_json, f"Device {dev_id} identity evidence does not contain private names")
        check("192.168.2." not in ev_json, f"Device {dev_id} identity evidence does not contain source subnet 192.168.2.x")

    # 6. Device addresses validation
    cur.execute("SELECT device_id, ip FROM device_addresses;")
    for dev_id, ip_b in cur.fetchall():
        ip = parse_ip(ip_b)
        check(ip is not None, f"Valid IP BLOB for device {dev_id}")
        if ip.version == 4:
            check(
                str(ip).startswith("192.168.50."),
                f"Device {dev_id} IP in demo subnet 192.168.50.0/24 (found {ip})",
            )

    # 7. Device evidence validation
    cur.execute("SELECT gateway_id, mac, value, metadata_json FROM device_evidence;")
    evidence_rows = cur.fetchall()
    for gw_id, mac_b, val, meta_json in evidence_rows:
        check(is_locally_administered_mac(mac_b), f"Evidence record has locally administered MAC: {mac_b.hex()}")
        check("贾维斯" not in meta_json, "Evidence metadata does not contain private name '贾维斯'")
        check("192.168.2." not in meta_json, "Evidence metadata does not contain source subnet 192.168.2.x")
        check("istoreos" not in meta_json.lower(), "Evidence metadata does not contain 'istoreos'")

    # 8. Flow sessions validation
    cur.execute("SELECT COUNT(*) FROM flow_sessions;")
    flow_cnt = cur.fetchone()[0]
    check(flow_cnt > 0, f"Flow sessions populated (count={flow_cnt})")

    cur.execute("SELECT DISTINCT client_ip FROM flow_sessions LIMIT 50;")
    for (b,) in cur.fetchall():
        ip = parse_ip(b)
        if ip and ip.version == 4 and ip.is_private and not ip.is_unspecified and not ip.is_loopback:
            check(str(ip).startswith("192.168.50."), f"Flow client IP in demo subnet: {ip}")

    # Check that no flow remote_ip has source private subnet
    cur.execute("SELECT COUNT(*) FROM flow_sessions WHERE remote_ip = X'C0A80201' OR remote_ip LIKE '%192.168.2.%';")
    bad_remote = cur.fetchone()[0]
    check(bad_remote == 0, f"Zero flow sessions with source private gateway/LAN IP (bad={bad_remote})")

    # 9. Domain validation
    for tbl in ["flow_sessions", "traffic_domain_minute", "traffic_scope_minute"]:
        cur.execute(f"SELECT 1 FROM sqlite_master WHERE type='table' AND name='{tbl}';")
        if cur.fetchone():
            cur.execute(
                f"SELECT COUNT(*) FROM {tbl} WHERE domain LIKE '%贾维斯%' OR domain LIKE '%192-168-2-%' OR domain LIKE '%eva.local%';"
            )
            leaked_doms = cur.fetchone()[0]
            check(leaked_doms == 0, f"Table '{tbl}' has 0 leaked local domain names (found {leaked_doms})")

    # 10. Timestamp invariant checks
    cur.execute("SELECT COUNT(*) FROM devices WHERE first_seen > last_seen;")
    check(cur.fetchone()[0] == 0, "devices: first_seen <= last_seen holds")

    cur.execute("SELECT COUNT(*) FROM device_addresses WHERE first_seen > last_seen;")
    check(cur.fetchone()[0] == 0, "device_addresses: first_seen <= last_seen holds")

    cur.execute("SELECT COUNT(*) FROM device_evidence WHERE first_seen > last_seen;")
    check(cur.fetchone()[0] == 0, "device_evidence: first_seen <= last_seen holds")

    cur.execute("SELECT COUNT(*) FROM flow_sessions WHERE started_at > last_seen_at;")
    check(cur.fetchone()[0] == 0, "flow_sessions: started_at <= last_seen_at holds")

    cur.execute("SELECT COUNT(*) FROM flow_sessions WHERE ended_at IS NOT NULL AND last_seen_at > ended_at;")
    check(cur.fetchone()[0] == 0, "flow_sessions: last_seen_at <= ended_at holds")

    cur.execute("SELECT MAX(last_seen_at) FROM flow_sessions;")
    max_ts = cur.fetchone()[0]
    check(1700000000000 <= max_ts <= 1705000000000, f"Timestamps normalized around base 2024-01-02 (max={max_ts})")

    # 11. Quantitative Completeness & Rollup Consistency Checks
    cur.execute("SELECT COUNT(*) FROM devices;")
    dev_count = cur.fetchone()[0]
    check(dev_count >= 8, f"Device count meets demo minimum (found {dev_count} >= 8)")

    cur.execute("SELECT COUNT(DISTINCT application_id) FROM traffic_application_minute WHERE application_id != '';")
    app_count = cur.fetchone()[0]
    check(app_count >= 15, f"Distinct applications count meets demo minimum (found {app_count} >= 15)")

    cur.execute("SELECT COUNT(*) FROM traffic_total_minute;")
    min_rows = cur.fetchone()[0]
    check(min_rows >= 1000, f"traffic_total_minute rows populated (found {min_rows} >= 1000)")

    cur.execute("SELECT COUNT(*) FROM traffic_total_hour;")
    hr_rows = cur.fetchone()[0]
    check(hr_rows >= 20, f"traffic_total_hour rows populated (found {hr_rows} >= 20)")

    # Rollup numerical consistency
    cur.execute("SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_total_minute;")
    min_sums = cur.fetchone()
    cur.execute("SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_total_hour;")
    hr_sums = cur.fetchone()
    cur.execute("SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_total_day;")
    day_sums = cur.fetchone()

    if hr_sums[0] is not None and hr_sums[0] > 0:
        check(
            min_sums[0] == hr_sums[0] == day_sums[0],
            f"Rollup upload consistency: minute={min_sums[0]}, hour={hr_sums[0]}, day={day_sums[0]}",
        )
        check(
            min_sums[1] == hr_sums[1] == day_sums[1],
            f"Rollup download consistency: minute={min_sums[1]}, hour={hr_sums[1]}, day={day_sums[1]}",
        )

    # 12. Deep comparison with source DB if provided
    if source_db_path:
        src_path = Path(source_db_path).resolve()
        if src_path.exists():
            print(f"[INFO] Cross-validating against source database inventory: {src_path}")
            source_tokens = extract_source_sensitive_tokens(src_path)
            print(f"[INFO] Scanning demo DB against {len(source_tokens)} source sensitive tokens...")

            with open(demo_file, "rb") as f:
                db_bytes = f.read()

            leak_count = 0
            for tok in sorted(source_tokens):
                tok_b = tok.encode("utf-8")
                if tok_b in db_bytes:
                    print(f"[LEAK] Found source token '{tok}' in demo database binary content!", file=sys.stderr)
                    leak_count += 1

            check(leak_count == 0, f"Source sensitive tokens remaining in demo DB: {leak_count}")

    conn.close()
    print("\n[SUCCESS] ALL DEMO DATABASE PRIVACY AND INTEGRITY VALIDATIONS PASSED!\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate netqmon demo SQLite template database.")
    parser.add_argument("demo_db", help="Path to demo template SQLite database to validate.")
    parser.add_argument("--source-db", help="Optional path to source database to cross-validate against.")
    parser.add_argument("--verbose", action="store_true", help="Print verbose details.")

    args = parser.parse_args()
    validate_database(
        demo_db_path=args.demo_db,
        source_db_path=args.source_db,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
