"""Decide whether a tagged release needs OpenWrt packages (Python 3.11+)."""

import copy
import os
import re
import subprocess
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_MAKEFILES = {
    "packaging/openwrt/netqmon/Makefile",
    "packaging/openwrt/luci-app-netqmon/Makefile",
}
INPUT_FILES = {
    ".github/workflows/openwrt.yml",
    ".dockerignore",
    "Cross.toml",
    "deploy/docker/Dockerfile.agent",
}
INPUT_DIRECTORIES = (
    "crates/agent/",
    "crates/protocol/",
    "bpf/",
    ".cargo/",
    "deploy/docker/cross/",
    "packaging/openwrt/",
    "scripts/release/",
)


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True)


def previous_tag(repo: Path, revision: str, tag: str) -> str | None:
    # Stable promotion must compare against the previous stable release, even
    # when a beta containing the same agent has already been published.
    matches = (
        ["--match", "v*-*"]
        if "-" in tag
        else ["--match", "v*", "--exclude", "v*-*"]
    )
    result = subprocess.run(
        [
            "git", "-C", str(repo), "describe", "--tags", "--abbrev=0",
            *matches, "--exclude", tag, revision,
        ],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def agent_lock_snapshot(contents: str) -> dict:
    """Compare only the agent's resolved dependency graph, including build deps."""
    packages = tomllib.loads(contents)["package"]

    def resolve(dependency: str) -> dict:
        parts = dependency.split()
        matches = [package for package in packages if package["name"] == parts[0]]
        if len(parts) > 1:
            matches = [package for package in matches if package["version"] == parts[1]]
        if len(parts) > 2:
            matches = [
                package for package in matches
                if package.get("source") == parts[2].strip("()")
            ]
        if len(matches) != 1:
            raise ValueError(f"Ambiguous or missing locked dependency: {dependency}")
        return matches[0]

    def identity(package: dict) -> tuple:
        return (
            package["name"],
            package.get("source", ""),
            package["version"] if "source" in package else "workspace",
        )

    result = {}

    def visit(package: dict) -> tuple:
        key = identity(package)
        if key not in result:
            value = copy.deepcopy(package)
            value["version"] = key[2]
            result[key] = value
            value["dependencies"] = sorted(
                visit(resolve(dependency))
                for dependency in package.get("dependencies", [])
            )
        return key

    visit(resolve("netqmon-agent"))
    return result


def relevant_change(repo: Path, base: str, revision: str, path: str) -> bool:
    def contents(ref: str) -> str:
        return git(repo, "show", f"{ref}:{path}")

    if path == "Cargo.toml":

        def manifest(ref: str) -> dict:
            value = tomllib.loads(contents(ref))
            value.get("workspace", {}).get("package", {}).pop("version", None)
            return value

        return manifest(base) != manifest(revision)
    if path == "Cargo.lock":
        return agent_lock_snapshot(contents(base)) != agent_lock_snapshot(contents(revision))
    if path in PACKAGE_MAKEFILES:

        def makefile(ref: str) -> str:
            return re.sub(
                r"(?m)^PKG_VERSION\s*:?=.*$", "PKG_VERSION:=<release>", contents(ref)
            )

        return makefile(base) != makefile(revision)
    if path.endswith(".md"):
        return False
    return (
        path in INPUT_FILES
        or path.startswith(INPUT_DIRECTORIES)
        or path.startswith("rust-toolchain")
    )


def detect(repo: Path, revision: str, tag: str, event: str) -> tuple[bool, str, str]:
    if event == "workflow_dispatch":
        return True, "", "Manual run requested"
    base = previous_tag(repo, revision, tag)
    if base is None:
        return True, "", "No earlier release tag in this channel; build conservatively"
    paths = git(
        repo, "diff", "--name-only", "--no-renames", "-z", base, revision
    ).split("\0")
    changed = [
        path for path in paths
        if path and relevant_change(repo, base, revision, path)
    ]
    if changed:
        return True, base, "Agent or packaging inputs changed: " + ", ".join(changed)
    return False, base, "Agent and packaging inputs unchanged (release version changes ignored)"


def main() -> None:
    try:
        build, base, reason = detect(
            ROOT, os.environ["GITHUB_SHA"], os.environ["GITHUB_REF_NAME"],
            os.environ["GITHUB_EVENT_NAME"],
        )
    except (subprocess.CalledProcessError, ValueError, KeyError) as error:
        # New/missing manifests and unfamiliar lock formats must never hide a
        # required release build. Manual dispatch can also force a rebuild.
        build, base, reason = (
            True, "", f"Could not compare release inputs; build conservatively: {error}"
        )
    print(reason)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"build={'true' if build else 'false'}\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write(
            f"### OpenWrt change detection\n\nBuild: **{build}**\n\n"
            f"Base: `{base or 'none'}`\n\n{reason}\n"
        )


if __name__ == "__main__":
    main()
