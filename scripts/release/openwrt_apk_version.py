#!/usr/bin/env python3
"""Convert a release version to an APK version with ordered prereleases."""

import re
import sys


def apk_version(version: str) -> str:
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.(\d+))?", version)
    if not match:
        raise ValueError(f"unsupported OpenWrt APK release version: {version}")
    base, stage, number = match.groups()
    return f"{base}_{stage}{number}" if stage else base


if __name__ == "__main__":
    try:
        print(apk_version(sys.argv[1]))
    except (IndexError, ValueError) as error:
        raise SystemExit(str(error)) from error
