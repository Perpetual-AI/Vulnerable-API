import unittest

import ssti


class TestSSTIVuln(unittest.TestCase):
    def test_normal_expression_rendered_as_literal(self):
        """Normal input should appear verbatim in the response."""
        response, status = ssti.sstivuln({"mathexp": "2+2"})
        self.assertEqual(status, 200)
        self.assertIn("2+2", response["msg"])

    def test_ssti_arithmetic_payload_not_evaluated(self):
        """{{7*7}} must not be evaluated to 49 — would indicate SSTI."""
        response, status = ssti.sstivuln({"mathexp": "{{7*7}}"})
        self.assertEqual(status, 200)
        # Safe: payload is echoed back as a literal string, NOT evaluated
        self.assertNotIn("49", response["msg"])
        self.assertIn("{{7*7}}", response["msg"])

    def test_ssti_rce_payload_not_executed(self):
        """OS command injection via Jinja2 config globals must not execute."""
        # `id` output is "uid=..." — only appears if the command actually ran.
        rce_payload = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
        response, status = ssti.sstivuln({"mathexp": rce_payload})
        self.assertEqual(status, 200)
        msg = response["msg"]
        # Safe: literal payload echoed back — Jinja2 {{ }} was not evaluated
        self.assertIn("popen", msg)
        # Safe: `id` was not executed — its output ("uid=") is absent
        self.assertNotIn("uid=", msg)

    def test_missing_mathexp_returns_400(self):
        _, status = ssti.sstivuln({"mathexp": ""})
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
