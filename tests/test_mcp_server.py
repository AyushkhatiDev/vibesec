"""Smoke test for the VibeSec MCP server tools.

Calls the tool functions directly (no MCP transport) to verify they
work end-to-end with the real rule engine.
"""
import json
import sys
import os
import tempfile

import pytest

# The mcp package requires Python >=3.10; skip this module entirely on
# older interpreters or when the optional [mcp] extra isn't installed.
pytest.importorskip("mcp")

# Ensure we can import from the local vibesec package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vibesec.mcp_server import check_code, check_file, check_diff, list_rules


def test_check_code_finds_hardcoded_secret():
    result = check_code(
        code='api_key = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"',
        filename="config.py",
    )
    print("=== check_code (hardcoded secret) ===")
    print(json.dumps(result, indent=2))
    assert not result["clean"], "Should detect hardcoded secret"
    assert result["summary"]["total"] > 0
    assert any("secret" in i["rule"].lower() or "key" in i["message"].lower() for i in result["issues"])
    print("✓ PASS\n")


def test_check_code_clean():
    result = check_code(
        code='import os\ndb_url = os.environ.get("DATABASE_URL")\n',
        filename="app.py",
    )
    print("=== check_code (clean code) ===")
    print(json.dumps(result, indent=2))
    assert result["clean"], "Clean code should have no issues"
    assert result["summary"]["total"] == 0
    print("✓ PASS\n")


def test_check_file():
    # Create a temp file with a known vulnerability
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="vibesec_test_"
    ) as f:
        f.write('password = "SuperSecret123!"\n')
        f.write('api_key = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"\n')
        tmp_path = f.name

    try:
        result = check_file(tmp_path)
        print("=== check_file (temp file with secrets) ===")
        print(json.dumps(result, indent=2))
        assert not result["clean"], "Should detect secrets in file"
        print("✓ PASS\n")
    finally:
        os.unlink(tmp_path)


def test_check_file_not_found():
    result = check_file("/nonexistent/path/foo.py")
    print("=== check_file (not found) ===")
    print(json.dumps(result, indent=2))
    assert "error" in result
    print("✓ PASS\n")


def test_check_diff():
    diff = """\
--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 import os
+api_key = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
 db = connect()
"""
    result = check_diff(diff, filename="config.py")
    print("=== check_diff (added secret) ===")
    print(json.dumps(result, indent=2))
    assert not result["clean"], "Should detect secret in added lines"
    print("✓ PASS\n")


def test_check_diff_clean():
    diff = """\
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 import os
+name = "hello"
 print(name)
"""
    result = check_diff(diff, filename="app.py")
    print("=== check_diff (clean addition) ===")
    print(json.dumps(result, indent=2))
    assert result["clean"], "Harmless addition should be clean"
    print("✓ PASS\n")


def test_list_rules():
    result = list_rules()
    print("=== list_rules ===")
    print(json.dumps(result, indent=2))
    assert result["count"] > 0, "Should have at least one rule"
    assert len(result["rules"]) == result["count"]
    print("✓ PASS\n")


if __name__ == "__main__":
    test_check_code_finds_hardcoded_secret()
    test_check_code_clean()
    test_check_file()
    test_check_file_not_found()
    test_check_diff()
    test_check_diff_clean()
    test_list_rules()
    print("=" * 40)
    print("All smoke tests passed!")
