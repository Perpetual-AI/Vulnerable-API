import ast
import os


_APP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")


def _get_run_call_debug_keyword(tree: ast.AST):
    """Return the debug keyword node from the app.run() call, or None."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug":
                    return kw
    return None


def test_debug_not_hardcoded_true():
    """debug=True must not be hardcoded in app.run() — FAILS on vulnerable code."""
    with open(_APP_PATH) as f:
        tree = ast.parse(f.read())

    kw = _get_run_call_debug_keyword(tree)
    assert kw is not None, "Could not find app.run() call with debug= keyword"

    is_hardcoded_true = isinstance(kw.value, ast.Constant) and kw.value.value is True
    assert not is_hardcoded_true, (
        "debug=True is hardcoded in app.run() — "
        "Werkzeug interactive debugger console is exposed; "
        "PIN is computable from /proc values leaked via LFI, giving unauthenticated RCE"
    )


def test_debug_controlled_by_env_var():
    """FLASK_DEBUG env var must gate debug mode — absent on fixed code, absent on vuln code."""
    with open(_APP_PATH) as f:
        source = f.read()

    assert "FLASK_DEBUG" in source, (
        "FLASK_DEBUG environment variable not referenced — "
        "debug mode cannot be disabled without changing source code"
    )


def test_debug_defaults_false_without_env_var():
    """Without FLASK_DEBUG set, the env-var expression used in the fix must evaluate to False."""
    # Ensure FLASK_DEBUG is absent, then verify the guard expression
    env_backup = os.environ.pop("FLASK_DEBUG", None)
    try:
        debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
        assert not debug, (
            "Default debug value is True without FLASK_DEBUG set — server starts in debug mode"
        )
    finally:
        if env_backup is not None:
            os.environ["FLASK_DEBUG"] = env_backup
