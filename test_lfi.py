import lfi


def test_lfi_absolute_path_blocked():
    """Absolute path traversal must be rejected — FAILS on vulnerable code."""
    result, status = lfi.lfivuln({"filename": "/etc/passwd"})
    assert status == 400, f"Absolute path traversal succeeded: {result}"


def test_lfi_dotdot_traversal_blocked():
    """../ traversal must be rejected — FAILS on vulnerable code."""
    result, status = lfi.lfivuln({"filename": "../../etc/shadow"})
    assert status == 400, f"Path traversal succeeded: {result}"


def test_lfi_proc_environ_blocked():
    """Environment variable leak via /proc/self/environ must be rejected."""
    result, status = lfi.lfivuln({"filename": "/proc/self/environ"})
    assert status == 400, f"/proc traversal succeeded: {result}"


def test_lfi_safe_file_allowed():
    """Legitimate filename within safe_files must still be served."""
    result, status = lfi.lfivuln({"filename": "readme.txt"})
    assert status == 200, f"Legitimate file was rejected: {result}"
