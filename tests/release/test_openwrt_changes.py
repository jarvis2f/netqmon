import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.release.detect_openwrt_changes import agent_lock_snapshot, detect, relevant_change


MANIFEST = '[workspace.package]\nversion = "1.0.0"\nedition = "2024"\n'
LOCK = '''version = 4
[[package]]
name = "netqmon-agent"
version = "1.0.0"
dependencies = ["netqmon-protocol", "lib 1.0.0"]
[[package]]
name = "netqmon-protocol"
version = "1.0.0"
dependencies = ["build-lib"]
[[package]]
name = "lib"
version = "1.0.0"
source = "registry+example"
checksum = "agent-dependency"
[[package]]
name = "lib"
version = "2.0.0"
source = "registry+example"
checksum = "collector-dependency"
[[package]]
name = "build-lib"
version = "1.0.0"
source = "registry+example"
checksum = "protocol-build-dependency"
[[package]]
name = "netqmon-collector"
version = "1.0.0"
dependencies = ["lib 2.0.0"]
'''


class OpenWrtChangesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release-test@example.invalid")
        # These fixtures create commits only in an isolated temporary repository.
        self.git("config", "core.hooksPath", str(self.repo / "no-hooks"))
        self.git("config", "commit.gpgsign", "false")
        self.write("Cargo.toml", MANIFEST)
        self.write("Cargo.lock", LOCK)
        self.write("crates/agent/src/main.rs", "fn main() {}\n")
        self.write("packaging/openwrt/netqmon/Makefile", "PKG_VERSION:=1.0.0\nPKG_RELEASE:=1\n")
        self.write("packaging/openwrt/luci-app-netqmon/Makefile", "PKG_VERSION:=1.0.0\nPKG_RELEASE:=1\n")
        self.commit()
        self.git("tag", "v1.0.0")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True)

    def write(self, path, content):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "release fixture")

    def decision(self, tag="v1.0.1", event="push"):
        return detect(self.repo, "HEAD", tag, event)

    def test_controller_ui_and_docs_changes_skip_builds(self):
        for path in ["crates/collector/src/main.rs", "apps/controller-ui/app/page.tsx", "crates/agent/README.md"]:
            self.write(path, "unrelated changes\n")
        self.commit()
        build, base, _ = self.decision()
        self.assertFalse(build)
        self.assertEqual(base, "v1.0.0")

    def test_agent_and_shared_build_inputs_trigger_builds(self):
        for path in [
            "crates/agent/src/main.rs", "crates/protocol/proto/schema.proto",
            "bpf/flow.bpf.c", "Cross.toml", "deploy/docker/Dockerfile.agent",
            "deploy/docker/cross/Dockerfile.armv7hf", ".cargo/config.toml",
            "packaging/openwrt/luci-app-netqmon/root/status.js",
            ".github/workflows/openwrt.yml", "scripts/release/build-openwrt-sdk.sh",
        ]:
            with self.subTest(path=path):
                self.write(path, "changed\n")
                self.commit()
                self.assertTrue(relevant_change(self.repo, "v1.0.0", "HEAD", path))

    def test_only_version_bumps_skip_builds(self):
        self.write("Cargo.toml", MANIFEST.replace('version = "1.0.0"', 'version = "1.0.1"'))
        # Only local workspace package versions change, not external dependencies.
        self.write("Cargo.lock", LOCK.replace('name = "netqmon-agent"\nversion = "1.0.0"', 'name = "netqmon-agent"\nversion = "1.0.1"').replace('name = "netqmon-protocol"\nversion = "1.0.0"', 'name = "netqmon-protocol"\nversion = "1.0.1"'))
        for path in ["packaging/openwrt/netqmon/Makefile", "packaging/openwrt/luci-app-netqmon/Makefile"]:
            self.write(path, "PKG_VERSION:=1.0.1\nPKG_RELEASE:=1\n")
        self.commit()
        self.assertFalse(self.decision()[0])

    def test_non_version_workspace_settings_trigger_builds(self):
        self.write("Cargo.toml", MANIFEST.replace('edition = "2024"', 'edition = "2027"'))
        self.commit()
        self.assertTrue(self.decision()[0])

    def test_package_revision_change_triggers_builds(self):
        self.write("packaging/openwrt/netqmon/Makefile", "PKG_VERSION:=1.0.1\nPKG_RELEASE:=2\n")
        self.commit()
        self.assertTrue(self.decision()[0])

    def test_collector_only_lock_changes_skip_builds(self):
        self.write("Cargo.lock", LOCK.replace("collector-dependency", "new-collector-dependency"))
        self.commit()
        self.assertFalse(self.decision()[0])

    def test_agent_and_transitive_build_dependency_updates_trigger_builds(self):
        for checksum in ["agent-dependency", "protocol-build-dependency"]:
            with self.subTest(checksum=checksum):
                self.write("Cargo.lock", LOCK.replace(checksum, "updated-checksum"))
                self.commit()
                self.assertTrue(self.decision()[0])

    def test_first_release_in_channel_builds(self):
        self.assertTrue(self.decision(tag="v1.1.0-beta.1")[0])
        self.git("tag", "-d", "v1.0.0")
        self.assertTrue(self.decision()[0])

    def test_manual_dispatch_builds_even_without_changes(self):
        self.assertFalse(self.decision()[0])
        self.assertTrue(self.decision(event="workflow_dispatch")[0])

    def test_same_commit_tag_does_not_skip_over_the_previous_release(self):
        self.git("tag", "v1.0.1")
        self.assertFalse(self.decision()[0])
        self.assertEqual(self.decision()[1], "v1.0.0")

    def test_stable_promotion_compares_to_previous_stable_not_beta(self):
        self.write("crates/agent/src/main.rs", "fn main() { println!(\"new agent\"); }\n")
        self.commit()
        self.git("tag", "v1.1.0-beta.1")
        self.write("Cargo.toml", MANIFEST.replace("1.0.0", "1.1.0"))
        self.commit()
        build, base, _ = self.decision(tag="v1.1.0")
        self.assertTrue(build)
        self.assertEqual(base, "v1.0.0")

    def test_prerelease_compares_to_previous_prerelease(self):
        self.git("tag", "v1.1.0-beta.1")
        self.write("crates/collector/src/main.rs", "controller only\n")
        self.commit()
        build, base, _ = self.decision(tag="v1.1.0-beta.2")
        self.assertFalse(build)
        self.assertEqual(base, "v1.1.0-beta.1")

    def test_deletions_and_renames_of_agent_files_trigger_builds(self):
        (self.repo / "crates/agent/src/main.rs").rename(self.repo / "moved.rs")
        self.commit()
        self.assertTrue(self.decision()[0])

    def test_ambiguous_lock_dependency_fails_instead_of_skipping(self):
        with self.assertRaises(ValueError):
            agent_lock_snapshot(LOCK.replace('"lib 1.0.0"', '"lib"'))


if __name__ == "__main__":
    unittest.main()
