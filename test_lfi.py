import unittest

import lfi


class TestLFIVuln(unittest.TestCase):
    def test_path_traversal_blocked(self):
        """../../../../etc/passwd must not be served — would succeed on vulnerable code."""
        _, status = lfi.lfivuln({"filename": "../../../../etc/passwd"})
        self.assertEqual(status, 400)

    def test_absolute_path_blocked(self):
        """/etc/passwd supplied as an absolute path must be rejected."""
        _, status = lfi.lfivuln({"filename": "/etc/passwd"})
        self.assertEqual(status, 400)

    def test_proc_environ_blocked(self):
        """/proc/self/environ leaks env vars including secrets; must be blocked."""
        _, status = lfi.lfivuln({"filename": "/proc/self/environ"})
        self.assertEqual(status, 400)

    def test_missing_filename_returns_400(self):
        _, status = lfi.lfivuln({"filename": ""})
        self.assertEqual(status, 400)

    def test_safe_filename_returns_200(self):
        """A filename that lives inside BASE_DIR (even if missing) should be attempted."""
        # readme.txt may or may not exist; what matters is status is 200, not 400
        _, status = lfi.lfivuln({"filename": "readme.txt"})
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
