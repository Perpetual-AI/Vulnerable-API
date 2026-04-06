"""
Proof tests for the path-traversal (LFI) fix in lfi.py.

Attack vectors exercised:
  1. Classic dot-dot traversal: ../../../etc/passwd
  2. Absolute path bypass: /etc/passwd
  3. Env-var leak: /proc/self/environ
  4. App source leak: ../lfi.py (relative to files/ base)

On the vulnerable code fetchfile() opens the name directly, so all of the
above would succeed (or silently fail only because the file doesn't exist in
the test environment). The fix jails reads to the <repo>/files/ directory and
returns "" for anything that escapes it.
"""

import lfi


# ---------------------------------------------------------------------------
# Attack-vector tests (would FAIL on the vulnerable code)
# ---------------------------------------------------------------------------

def test_dotdot_traversal_blocked():
    """../../../etc/passwd must return "" — not the file contents."""
    result = lfi.fetchfile("../../../etc/passwd")
    assert result == "", (
        f"Path traversal succeeded! Got: {result[:80]!r}"
    )


def test_absolute_path_blocked():
    """/etc/passwd (absolute) must return "" even though it exists on most systems."""
    result = lfi.fetchfile("/etc/passwd")
    assert result == "", (
        f"Absolute-path bypass succeeded! Got: {result[:80]!r}"
    )


def test_app_source_not_readable():
    """../lfi.py must not be readable from the files/ jail."""
    result = lfi.fetchfile("../lfi.py")
    assert result == "", (
        f"App source leaked! Got: {result[:80]!r}"
    )


def test_proc_environ_blocked():
    """/proc/self/environ must not leak env vars."""
    result = lfi.fetchfile("/proc/self/environ")
    assert result == "", (
        f"/proc/self/environ leaked! Got: {result[:80]!r}"
    )


# ---------------------------------------------------------------------------
# Legitimate access still works (regression guard)
# ---------------------------------------------------------------------------

def test_allowed_file_readable(tmp_path):
    """A file actually inside the jail must be readable."""
    # Point _BASE at a real tmpdir so we control the content.
    allowed = tmp_path / "hello.txt"
    allowed.write_text("hello world")

    original_base = lfi._BASE
    lfi._BASE = str(tmp_path)
    try:
        result = lfi.fetchfile("hello.txt")
    finally:
        lfi._BASE = original_base

    assert result == "hello world", (
        f"Legitimate file read failed! Got: {result!r}"
    )


def test_nonexistent_file_returns_empty():
    """Missing files return "" without raising."""
    result = lfi.fetchfile("nonexistent_file_xyz.txt")
    assert result == ""


# ---------------------------------------------------------------------------
# lfivuln() integration — the HTTP-level entry point
# ---------------------------------------------------------------------------

def test_lfivuln_traversal_returns_200_empty():
    """
    POST /api/lfivuln with a traversal payload must not expose file contents.
    The endpoint returns 200 with an empty fetchfile result.
    """
    payload = {"filename": "../../../etc/passwd"}
    response, status = lfi.lfivuln(payload)
    assert status == 200
    # The msg must not contain typical /etc/passwd content.
    assert "root:" not in response["msg"], (
        f"passwd file exposed via lfivuln! Response: {response['msg'][:80]!r}"
    )
