import unittest

from scripts.release.openwrt_apk_version import apk_version


class OpenWrtApkVersionTests(unittest.TestCase):
    def test_release_versions_use_apk_prerelease_syntax(self):
        self.assertEqual(apk_version("1.1.1-beta.5"), "1.1.1_beta5")
        self.assertEqual(apk_version("1.1.1-beta.10"), "1.1.1_beta10")
        self.assertEqual(apk_version("1.1.1-rc.1"), "1.1.1_rc1")
        self.assertEqual(apk_version("1.1.1"), "1.1.1")

    def test_unsupported_prerelease_does_not_publish_a_hash_version(self):
        with self.assertRaises(ValueError):
            apk_version("1.1.1-experimental.1")
