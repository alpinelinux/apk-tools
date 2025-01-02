import unittest
import apk


class TestApkModule(unittest.TestCase):
    def test_version_validate(self):
        self.assertTrue(apk.version_validate("1.0"))
        self.assertFalse(apk.version_validate("invalid-version"))

    def test_version_compare(self):
        self.assertEqual(apk.version_compare("1.0", "1.0"), apk.VERSION_EQUAL)
        self.assertEqual(apk.version_compare("1.0", "2.0"), apk.VERSION_LESS)
        self.assertTrue(apk.version_compare("2.0", "1.0"), apk.VERSION_GREATER)

    def test_version_match(self):
        self.assertTrue(apk.version_match("1.0", apk.VERSION_EQUAL, "1.0"))
        self.assertFalse(apk.version_match("1.0", apk.VERSION_LESS, "1.0"))


if __name__ == "__main__":
    unittest.main()
