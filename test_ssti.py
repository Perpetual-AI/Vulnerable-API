import pytest
import ssti


def test_ssti_rce_payload_blocked():
    """Template injection payload must not execute — FAILS on vulnerable code."""
    payload = {"mathexp": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"}
    result, status = ssti.sstivuln(payload)
    # Vulnerable code: renders the payload as a Jinja2 template → executes id command
    # Fixed code: treats input as data → returns the literal string unchanged
    assert status == 200
    msg = result["msg"]
    assert msg.startswith("my temp: "), f"Unexpected response: {msg}"
    assert "uid=" not in msg, f"RCE succeeded — shell output leaked: {msg}"


def test_ssti_expression_treated_as_literal():
    """Jinja2 arithmetic expression must be returned literally, not evaluated."""
    payload = {"mathexp": "{{7*7}}"}
    result, status = ssti.sstivuln(payload)
    assert status == 200
    # Vulnerable: returns "my temp: 49"; Fixed: returns "my temp: {{7*7}}"
    assert "49" not in result["msg"], f"Expression was evaluated: {result['msg']}"


def test_ssti_normal_input_works():
    """Legitimate input must still pass through correctly."""
    payload = {"mathexp": "hello"}
    result, status = ssti.sstivuln(payload)
    assert status == 200
    assert result["msg"] == "my temp: hello"
