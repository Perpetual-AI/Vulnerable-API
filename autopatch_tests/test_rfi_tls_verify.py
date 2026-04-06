"""
Test: requests.get() in rfi.py must NOT use verify=False.
CVE class: insecure_defaults — disabling TLS certificate verification allows
MITM attackers to intercept and substitute HTTPS responses silently.

Attack vector: a network attacker between the server and the fetched HTTPS URL
can present a forged certificate (the error is silenced) and inject arbitrary
content into the response, which may then be trusted or processed further.

This test inspects rfi.py via AST so it does NOT require starting the server.
It would FAIL on the vulnerable code (verify=False) and PASS after the fix.
"""

import ast
import os

RFI_PATH = os.path.join(os.path.dirname(__file__), "..", "rfi.py")


def _requests_get_verify_values():
    """
    Walk rfi.py's AST and collect every value passed as the `verify` keyword
    argument to any requests.get() call.
    """
    with open(RFI_PATH) as f:
        tree = ast.parse(f.read())

    verify_values = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Match requests.get(...)
        func = node.func
        is_requests_get = (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and isinstance(func.value, ast.Name)
            and func.value.id == "requests"
        )
        if not is_requests_get:
            continue
        for kw in node.keywords:
            if kw.arg == "verify":
                verify_values.append(kw.value)
    return verify_values


def test_verify_false_not_present():
    """
    verify=False must not appear in any requests.get() call in rfi.py.

    The vulnerable original code contained:
        requests.get(url=name, timeout=2, verify=False)
    which silences TLS certificate errors, enabling MITM interception of every
    outbound HTTPS fetch made by the RFI endpoint.
    """
    for value_node in _requests_get_verify_values():
        assert not (
            isinstance(value_node, ast.Constant) and value_node.value is False
        ), (
            "requests.get(..., verify=False) found in rfi.py — TLS certificate "
            "verification is disabled, enabling silent MITM interception of all "
            "outbound HTTPS requests."
        )


def test_tls_verification_is_enabled_by_default():
    """
    Either verify= is absent (requests defaults to True) or it is explicitly
    set to a non-False value.  Both are acceptable; verify=False is not.
    """
    for value_node in _requests_get_verify_values():
        if isinstance(value_node, ast.Constant):
            assert value_node.value is not False, (
                "verify= must not be False; omit it or set it to True / a CA path."
            )
