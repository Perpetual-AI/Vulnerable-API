import ast
import os

_CUSTOM_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom_db.py")


def test_no_hardcoded_credentials_in_source():
    """Plaintext credentials must NOT appear as string literals in custom_db.py.

    Reproduces the attack vector: FAILS on the vulnerable code where 'mike',
    'kaines', and 'admin' are embedded directly in INSERT statements, meaning
    any reader of the source has the full credential set.
    """
    with open(_CUSTOM_DB_PATH) as f:
        source = f.read()

    tree = ast.parse(source)
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]

    for literal in literals:
        assert "kaines" not in literal, (
            "Hardcoded password 'kaines' found as a string literal in custom_db.py. "
            "Load credentials from environment variables instead."
        )


def test_setup_db_references_env_vars():
    """setup_db() must reference environment variables for credentials."""
    with open(_CUSTOM_DB_PATH) as f:
        source = f.read()

    assert "os.environ" in source or "os.getenv" in source, (
        "custom_db.py does not reference environment variables — "
        "credentials are not loaded from a secure source"
    )
