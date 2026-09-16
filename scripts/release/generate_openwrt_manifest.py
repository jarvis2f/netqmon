#!/usr/bin/env python3
"""Create the channel manifest for OpenWrt packages in one or more releases."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path


MANIFEST_NAME = "openwrt-agent-manifest.json"
PACKAGE_NAMES = {"netqmon-agent", "luci-app-netqmon"}


def read_control(path: Path) -> dict[str, str]:
    with tarfile.open(path, mode="r:*") as package:
        control_archive = next(
            (
                member
                for member in package.getmembers()
                if member.name.lstrip("./") == "control.tar.gz"
            ),
            None,
        )
        if control_archive is None:
            raise ValueError(f"{path.name}: package has no control.tar.gz")
        control_bytes = package.extractfile(control_archive)
        if control_bytes is None:
            raise ValueError(f"{path.name}: cannot read control.tar.gz")
        with tarfile.open(fileobj=io.BytesIO(control_bytes.read()), mode="r:gz") as control:
            member = next(
                (item for item in control.getmembers() if item.name.lstrip("./") == "control"),
                None,
            )
            if member is None:
                raise ValueError(f"{path.name}: package control file is missing")
            contents = control.extractfile(member)
            if contents is None:
                raise ValueError(f"{path.name}: cannot read package control file")
            fields: dict[str, str] = {}
            for line in contents.read().decode("utf-8").splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    fields[key.strip()] = value.strip()
            return fields


def package_record(path: Path, repository: str, tag: str) -> dict[str, str] | None:
    fields = read_control(path)
    name = fields.get("Package", "")
    if name not in PACKAGE_NAMES:
        return None

    architecture = fields.get("Architecture", "")
    version = fields.get("Version", "")
    if not architecture or not version:
        raise ValueError(f"{path.name}: package architecture or version is missing")

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "name": name,
        "openwrt_arch": architecture,
        "version": version,
        "url": f"https://github.com/{repository}/releases/download/{tag}/{path.name}",
        "sha256": digest,
    }


def parse_release(specification: str) -> tuple[str, str, Path]:
    try:
        channel, tag, directory = specification.split(":", 2)
    except ValueError as error:
        raise ValueError("release must use CHANNEL:TAG:PACKAGE_DIRECTORY") from error
    if channel not in {"stable", "beta"}:
        raise ValueError(f"unsupported channel: {channel}")
    if not tag.startswith("v") or len(tag) == 1:
        raise ValueError(f"release tag must start with v: {tag}")
    package_directory = Path(directory)
    if not package_directory.is_dir():
        raise ValueError(f"package directory does not exist: {package_directory}")
    return channel, tag, package_directory


def create_manifest(repository: str, releases: list[str]) -> dict[str, object]:
    channels: dict[str, dict[str, object]] = {}
    for specification in releases:
        channel, tag, directory = parse_release(specification)
        if channel in channels:
            raise ValueError(f"channel was specified more than once: {channel}")

        packages: dict[tuple[str, str], dict[str, str]] = {}
        for path in sorted(directory.rglob("*.ipk")):
            record = package_record(path, repository, tag)
            if record is None:
                continue
            key = (record["name"], record["openwrt_arch"])
            previous = packages.get(key)
            if previous is not None and previous["sha256"] != record["sha256"]:
                raise ValueError(
                    f"duplicate {key[0]} package for {key[1]} has differing contents"
                )
            packages[key] = record

        agent_packages = [record for (name, _), record in packages.items() if name == "netqmon-agent"]
        luci_packages = [record for (name, _), record in packages.items() if name == "luci-app-netqmon"]
        if not agent_packages:
            raise ValueError(f"{tag}: no netqmon-agent packages found")
        if not any(record["openwrt_arch"] == "all" for record in luci_packages):
            raise ValueError(f"{tag}: no architecture-independent LuCI package found")

        channels[channel] = {
            "version": tag[1:],
            "packages": sorted(packages.values(), key=lambda record: (record["name"], record["openwrt_arch"])),
        }

    return {
        "format": "netqmon-openwrt-agent",
        "format_version": 1,
        "channels": channels,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="GitHub owner/repository")
    parser.add_argument(
        "--release",
        action="append",
        required=True,
        help="CHANNEL:TAG:PACKAGE_DIRECTORY; may be repeated to combine channels",
    )
    parser.add_argument("--output", type=Path, default=Path(MANIFEST_NAME))
    args = parser.parse_args()

    try:
        manifest = create_manifest(args.repository, args.release)
        args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    except (OSError, tarfile.TarError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
