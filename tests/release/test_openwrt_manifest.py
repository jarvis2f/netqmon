import hashlib
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.release.generate_openwrt_manifest import create_manifest


def make_ipk(
    path: Path,
    package: str,
    architecture: str,
    version: str,
    data_payload: bytes = b"test-data",
) -> None:
    control_buffer = io.BytesIO()
    with tarfile.open(fileobj=control_buffer, mode="w:gz") as control_archive:
        control = f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
        payload = control.encode()
        info = tarfile.TarInfo("./control")
        info.size = len(payload)
        control_archive.addfile(info, io.BytesIO(payload))

    package_buffer = io.BytesIO()
    with tarfile.open(fileobj=package_buffer, mode="w:gz") as package_archive:
        for name, contents in (
            ("./debian-binary", b"2.0\n"),
            ("./control.tar.gz", control_buffer.getvalue()),
            ("./data.tar.gz", data_payload),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(contents)
            package_archive.addfile(info, io.BytesIO(contents))
    path.write_bytes(package_buffer.getvalue())


def make_apk_artifact(
    root: Path,
    package: str,
    architecture: str,
    version: str,
    payload: bytes = b"test-apk-data",
) -> Path:
    artifact = root / f"openwrt-{architecture}-apk"
    artifact.mkdir(parents=True, exist_ok=True)
    path = artifact / f"{package}-{version}_{architecture}.apk"
    path.write_bytes(payload)
    return path


class OpenWrtManifestTests(unittest.TestCase):
    def test_manifest_contains_versioned_architecture_assets_and_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stable = root / "stable"
            beta = root / "beta"
            stable.mkdir()
            beta.mkdir()
            agent = stable / "netqmon-agent_0.1.0-beta.4-r1_x86_64.ipk"
            luci = stable / "luci-app-netqmon_0.1.0-beta.4-r1_all.ipk"
            make_ipk(agent, "netqmon-agent", "x86_64", "0.1.0-beta.4-r1")
            make_ipk(luci, "luci-app-netqmon", "all", "0.1.0-beta.4-r1")
            make_ipk(
                beta / "netqmon-agent_0.1.0-beta.9-r1_x86_64.ipk",
                "netqmon-agent",
                "x86_64",
                "0.1.0-beta.9-r1",
            )
            make_ipk(
                beta / "luci-app-netqmon_0.1.0-beta.9-r1_all.ipk",
                "luci-app-netqmon",
                "all",
                "0.1.0-beta.9-r1",
            )

            manifest = create_manifest(
                "jarvis2f/netqmon",
                [
                    f"stable:v0.1.0-beta.4:{stable}",
                    f"beta:v0.1.0-beta.9:{beta}",
                ],
            )

            self.assertEqual(manifest["channels"]["stable"]["version"], "0.1.0-beta.4")
            self.assertEqual(manifest["channels"]["beta"]["version"], "0.1.0-beta.9")
            record = next(
                item
                for item in manifest["channels"]["beta"]["packages"]
                if item["name"] == "netqmon-agent"
            )
            package_path = beta / "netqmon-agent_0.1.0-beta.9-r1_x86_64.ipk"
            self.assertEqual(record["openwrt_arch"], "x86_64")
            self.assertEqual(record["package_format"], "ipk")
            self.assertEqual(
                record["url"],
                "https://github.com/jarvis2f/netqmon/releases/download/v0.1.0-beta.9/"
                "netqmon-agent_0.1.0-beta.9-r1_x86_64.ipk",
            )
            self.assertEqual(record["sha256"], hashlib.sha256(package_path.read_bytes()).hexdigest())

    def test_manifest_rejects_differing_duplicate_architecture_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_ipk(root / "netqmon-agent-x86.ipk", "netqmon-agent", "x86_64", "1-r1")
            make_ipk(
                root / "netqmon-agent-x86-copy.ipk",
                "netqmon-agent",
                "x86_64",
                "1-r1",
                data_payload=b"different package data",
            )
            make_ipk(root / "luci.ipk", "luci-app-netqmon", "all", "1-r1")

            with self.assertRaisesRegex(ValueError, "differing contents"):
                create_manifest("jarvis2f/netqmon", [f"beta:v1.0.0-beta.1:{root}"])

    def test_manifest_contains_ipk_and_apk_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_ipk(root / "netqmon-agent_1.0.0-r1_x86_64.ipk", "netqmon-agent", "x86_64", "1.0.0-r1")
            make_ipk(root / "luci-app-netqmon_1.0.0-r1_all.ipk", "luci-app-netqmon", "all", "1.0.0-r1")
            apk = make_apk_artifact(root, "netqmon-agent", "x86_64", "1.0.0-r1")
            make_apk_artifact(root, "luci-app-netqmon", "x86_64", "1.0.0-r1")

            manifest = create_manifest("jarvis2f/netqmon", [f"stable:v1.0.0:{root}"])

            self.assertEqual(manifest["format_version"], 2)
            packages = manifest["channels"]["stable"]["packages"]
            self.assertEqual([record["package_format"] for record in packages[:2]], ["ipk", "ipk"])
            agent_records = [
                record
                for record in packages
                if record["name"] == "netqmon-agent" and record["openwrt_arch"] == "x86_64"
            ]
            self.assertEqual([record["package_format"] for record in agent_records], ["ipk", "apk"])
            self.assertEqual(agent_records[1]["version"], "1.0.0-r1")
            self.assertEqual(agent_records[1]["sha256"], hashlib.sha256(apk.read_bytes()).hexdigest())
            self.assertTrue(agent_records[1]["url"].endswith("netqmon-agent-1.0.0-r1_x86_64.apk"))

    def test_manifest_preserves_riscv_architecture_for_each_package_format(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_ipk(root / "agent.ipk", "netqmon-agent", "riscv64_riscv64", "1.1.0-beta.1-r1")
            make_ipk(root / "luci.ipk", "luci-app-netqmon", "all", "1.1.0-beta.1-r1")
            make_apk_artifact(root, "netqmon-agent", "riscv64_generic", "1.1.0~03d585d-r1")

            manifest = create_manifest("jarvis2f/netqmon", [f"beta:v1.1.0-beta.1:{root}"])
            records = [
                (record["package_format"], record["openwrt_arch"])
                for record in manifest["channels"]["beta"]["packages"]
                if record["name"] == "netqmon-agent"
            ]
            self.assertEqual(records, [("ipk", "riscv64_riscv64"), ("apk", "riscv64_generic")])

    def test_beta_apk_urls_match_github_normalized_asset_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_ipk(root / "luci.ipk", "luci-app-netqmon", "all", "1.1.0-beta.1-r1")
            version = "1.1.0~03d585d-r1"
            paths = [
                make_apk_artifact(root, name, "x86_64", version)
                for name in ("netqmon-agent", "luci-app-netqmon")
            ]

            manifest = create_manifest("jarvis2f/netqmon", [f"beta:v1.1.0-beta.1:{root}"])

            records = {
                record["name"]: record
                for record in manifest["channels"]["beta"]["packages"]
                if record["package_format"] == "apk"
            }
            self.assertEqual(len(records), 2)
            for path in paths:
                name = path.name.split("-1.1.0~", 1)[0]
                record = records[name]
                self.assertEqual(record["version"], version)
                self.assertEqual(
                    record["url"],
                    "https://github.com/jarvis2f/netqmon/releases/download/v1.1.0-beta.1/"
                    f"{name}-1.1.0.03d585d-r1_x86_64.apk",
                )
                self.assertEqual(record["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_ordered_beta_apk_version_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_ipk(root / "luci.ipk", "luci-app-netqmon", "all", "1.1.1-beta.5-r1")
            make_apk_artifact(root, "netqmon-agent", "x86_64", "1.1.1_beta5-r1")
            manifest = create_manifest("jarvis2f/netqmon", [f"beta:v1.1.1-beta.5:{root}"])
            package = next(item for item in manifest["channels"]["beta"]["packages"] if item["package_format"] == "apk")
            self.assertEqual(package["version"], "1.1.1_beta5-r1")
            self.assertTrue(package["url"].endswith("netqmon-agent-1.1.1_beta5-r1_x86_64.apk"))

    def test_manifest_rejects_apk_without_artifact_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_ipk(root / "netqmon-agent_1.0.0-r1_x86_64.ipk", "netqmon-agent", "x86_64", "1.0.0-r1")
            make_ipk(root / "luci-app-netqmon_1.0.0-r1_all.ipk", "luci-app-netqmon", "all", "1.0.0-r1")
            (root / "netqmon-agent-1.0.0-r1_x86_64.apk").write_bytes(b"invalid-location")

            with self.assertRaisesRegex(ValueError, "artifact directory"):
                create_manifest("jarvis2f/netqmon", [f"stable:v1.0.0:{root}"])


if __name__ == "__main__":
    unittest.main()
