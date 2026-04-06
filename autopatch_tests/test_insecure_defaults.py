"""
Test: debug mode must be disabled in app.py
CVE class: insecure_defaults — Flask debug=True exposes Werkzeug REPL via network.
This test parses app.py directly so it does NOT require starting the server.
It would FAIL on the vulnerable code (debug=True) and PASS after the fix (debug=False).
"""

import ast
import os

APP_PATH = os.path.join(os.path.dirname(__file__), "..", "app.py")


def _get_app_run_kwargs():
    """Parse app.py and return kwargs passed to app.run()."""
    with open(APP_PATH) as f:
        tree = ast.parse(f.read())

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
        ):
            return {kw.arg: kw.value for kw in node.keywords}
    return {}


def test_debug_is_not_true():
    """app.run() must not pass debug=True — that enables the Werkzeug REPL on errors."""
    kwargs = _get_app_run_kwargs()
    assert "debug" in kwargs, "app.run() has no debug kwarg — add debug=False explicitly"
    debug_value = kwargs["debug"]
    # The AST value should be a NameConstant/Constant False, not True
    assert isinstance(debug_value, ast.Constant), "debug= must be a boolean literal"
    assert debug_value.value is not True, (
        "debug=True is present in app.run() — this exposes the Werkzeug interactive "
        "debugger REPL on all network interfaces without authentication (RCE risk)"
    )


def test_debug_is_explicitly_false():
    """Require debug=False to be explicit, preventing accidental re-enablement."""
    kwargs = _get_app_run_kwargs()
    debug_value = kwargs.get("debug")
    assert debug_value is not None, "debug kwarg missing from app.run()"
    assert isinstance(debug_value, ast.Constant) and debug_value.value is False, (
        "debug must be explicitly set to False"
    )
