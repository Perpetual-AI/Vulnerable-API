"""
Proof tests for the SSTI fix in ssti.py.

The attack vector: POST /api/sstivuln with mathexp containing a Jinja2
expression that accesses Python internals to execute OS commands.

On the vulnerable code  → Template("my temp: " + exp)  the expression is
compiled as template code and executed.
On the fixed code       → Template("my temp: {{ value }}").render(value=exp)
the expression is treated as a plain string and returned literally.
"""

from ssti import sstivuln


ATTACK_PAYLOAD = "{{''.__class__.__mro__[1].__subclasses__()}}"
BENIGN_INPUT = "1+1"


def test_ssti_attack_payload_not_executed():
    """
    The RCE payload must NOT be evaluated — it should be returned as a
    literal string, not expanded into a list of subclasses (or worse, used
    to run shell commands).

    This test would FAIL on the vulnerable code because Jinja2 would
    evaluate the expression and return a stringified list of classes.
    """
    result, status = sstivuln({"mathexp": ATTACK_PAYLOAD})
    msg = result["msg"]

    # The raw payload must appear verbatim in the output, not be evaluated.
    assert msg == f"my temp: {ATTACK_PAYLOAD}", (
        f"SSTI payload was executed! Got: {msg!r}"
    )
    assert status == 200


def test_ssti_os_command_injection_not_executed():
    """
    Attempt to use os.popen via the subclass chain. On the fixed code the
    expression must appear as a literal string, not produce command output.
    """
    cmd_payload = "{{''.__class__.__mro__[1].__subclasses__()[273].__init__.__globals__['os'].popen('id').read()}}"
    result, status = sstivuln({"mathexp": cmd_payload})
    msg = result["msg"]

    # Must not contain typical `id` output like "uid="
    assert "uid=" not in msg, f"OS command was executed via SSTI! Got: {msg!r}"
    assert msg == f"my temp: {cmd_payload}"
    assert status == 200


def test_benign_input_returned_as_literal():
    """Normal math-like strings are returned verbatim (not evaluated)."""
    result, status = sstivuln({"mathexp": BENIGN_INPUT})
    assert result["msg"] == f"my temp: {BENIGN_INPUT}"
    assert status == 200


def test_default_value_when_key_missing():
    """Missing mathexp key falls back to the default 'test' value."""
    result, status = sstivuln({})
    assert result["msg"] == "my temp: test"
    assert status == 200
