import unittest
from unittest.mock import patch, MagicMock

import rfi


class TestRFIVuln(unittest.TestCase):
    def test_aws_metadata_ssrf_blocked(self):
        """POST with AWS metadata URL must be rejected — would succeed on vulnerable code."""
        result, status = rfi.rfivuln({"imagelink": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
        self.assertEqual(status, 200)
        self.assertNotIn("security-credentials", result.get("msg", ""))
        # Confirm fetchimage itself returns empty for this URL
        self.assertEqual(rfi.fetchimage("http://169.254.169.254/latest/meta-data/"), "")

    def test_localhost_ssrf_blocked(self):
        """Probing localhost services (e.g. Redis on :6379) must be blocked."""
        self.assertEqual(rfi.fetchimage("http://127.0.0.1:6379"), "")
        self.assertEqual(rfi.fetchimage("http://localhost/admin"), "")

    def test_private_ip_10_blocked(self):
        """10.x internal network must be blocked."""
        self.assertEqual(rfi.fetchimage("http://10.0.0.1/secret"), "")

    def test_private_ip_192168_blocked(self):
        """192.168.x internal network must be blocked."""
        self.assertEqual(rfi.fetchimage("http://192.168.1.1/router"), "")

    def test_private_ip_172_blocked(self):
        """172.16-31.x internal network must be blocked."""
        self.assertEqual(rfi.fetchimage("http://172.16.0.1/"), "")

    def test_file_scheme_blocked(self):
        """file:// scheme must be rejected to prevent local file reads."""
        self.assertEqual(rfi.fetchimage("file:///etc/passwd"), "")

    def test_missing_imagelink_returns_400(self):
        """Empty imagelink should return 400."""
        _, status = rfi.rfivuln({"imagelink": ""})
        self.assertEqual(status, 400)

    def test_safe_external_url_allowed(self):
        """A real external URL with a valid public IP should pass the URL check."""
        mock_response = MagicMock()
        mock_response.text = "image data"
        with patch("rfi.requests.get", return_value=mock_response), \
             patch("rfi.socket.gethostbyname", return_value="93.184.216.34"):  # example.com
            result = rfi.fetchimage("http://example.com/image.png")
        self.assertEqual(result, "image data")

    def test_tls_verification_enabled(self):
        """requests.get must be called without verify=False (TLS must be verified)."""
        mock_response = MagicMock()
        mock_response.text = "ok"
        with patch("rfi.requests.get", return_value=mock_response) as mock_get, \
             patch("rfi.socket.gethostbyname", return_value="93.184.216.34"):
            rfi.fetchimage("https://example.com/image.png")
        call_kwargs = mock_get.call_args[1]
        self.assertNotEqual(call_kwargs.get("verify"), False)


if __name__ == "__main__":
    unittest.main()
