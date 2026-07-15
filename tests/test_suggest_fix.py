"""Tests for suggest_fix — fix templates, diff extraction, and MCP tool."""

import os
from unittest.mock import patch, MagicMock

import pytest

from vibesec.fix_templates import get_template, FIX_TEMPLATES
from vibesec.fixgen import (
    _extract_surrounding_context,
    _extract_diff,
    generate_fix_diff,
)


# ---------------------------------------------------------------------------
# Fix template coverage
# ---------------------------------------------------------------------------

class TestFixTemplates:
    """Every rule in ALL_RULES should have a fix template."""

    KNOWN_RULES = [
        "Hardcoded Secret",
        "Supabase RLS Disabled",
        "SQL Injection Risk",
        "Missing Route Authentication",
        "Hallucinated Package",
        "Source Map Exposure",
        "Unsafe JWT Handling",
        "Client-Side Role Trust",
        "Insecure Flask Configuration",
        "Credentials in Environment File",
        "Unsafe HTML Injection (XSS)",
        "Missing Webhook Verification",
        "Permissive CORS Configuration",
        "Command Injection",
        "Path Traversal",
        "Server-Side Request Forgery",
        "Insecure Deserialization",
        "Server-Side Template Injection",
        "Weak Cryptography",
        "Open Redirect",
        "Node.js Security Misconfiguration",
        "Next.js Security Issue",
        "Docker Security Issue",
        "GitHub Actions Security Issue",
    ]

    def test_all_rules_have_templates(self):
        for rule_name in self.KNOWN_RULES:
            template = get_template(rule_name)
            assert template is not None, f"No template for {rule_name}"
            assert "ai_pattern" in template
            assert "canonical_fix" in template
            assert "diff_instruction" in template
            assert "pitfalls" in template
            assert "confidence" in template

    def test_template_count_matches_rules(self):
        assert len(FIX_TEMPLATES) == 24

    def test_exact_match(self):
        t = get_template("SQL Injection Risk")
        assert "parameterized" in t["canonical_fix"].lower()

    def test_fuzzy_match(self):
        t = get_template("sql injection risk")
        assert "parameterized" in t["canonical_fix"].lower()

    def test_unknown_rule_returns_fallback(self):
        t = get_template("Completely Unknown Rule XYZ")
        assert t["confidence"] == "low"
        assert "ai_pattern" in t


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------

class TestExtractSurroundingContext:
    def test_marks_target_line(self):
        content = "\n".join(f"line {i}" for i in range(1, 31))
        ctx = _extract_surrounding_context(content, 15, window=3)
        assert ">>>" in ctx
        assert "line 15" in ctx

    def test_handles_first_line(self):
        content = "first\nsecond\nthird"
        ctx = _extract_surrounding_context(content, 1, window=2)
        assert ">>>" in ctx
        assert "first" in ctx

    def test_handles_last_line(self):
        content = "first\nsecond\nthird"
        ctx = _extract_surrounding_context(content, 3, window=2)
        assert ">>>" in ctx
        assert "third" in ctx

    def test_empty_content(self):
        assert _extract_surrounding_context("", 1) == ""

    def test_invalid_line(self):
        assert _extract_surrounding_context("hello", 0) == ""


# ---------------------------------------------------------------------------
# Diff extraction from LLM response
# ---------------------------------------------------------------------------

class TestExtractDiff:
    def test_fenced_diff_block(self):
        response = '''Here's the fix:

```diff
--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
 import os
-password = "hunter2"
+password = os.environ.get("PASSWORD")
```

This replaces the hardcoded password with an environment variable.'''

        diff = _extract_diff(response)
        assert "--- a/app.py" in diff
        assert "+++ b/app.py" in diff
        assert '-password = "hunter2"' in diff
        assert "+password = os.environ" in diff

    def test_unfenced_diff(self):
        response = """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-password = "secret"
+password = os.environ["PASSWORD"]
Done."""

        diff = _extract_diff(response)
        assert "--- a/app.py" in diff

    def test_no_diff_returns_empty(self):
        response = "Just use environment variables instead of hardcoding."
        assert _extract_diff(response) == ""

    def test_fenced_block_without_diff_label(self):
        response = '''```
--- a/config.py
+++ b/config.py
@@ -1 +1 @@
-SECRET = "abc"
+SECRET = os.getenv("SECRET")
```'''
        diff = _extract_diff(response)
        assert "SECRET" in diff


# ---------------------------------------------------------------------------
# generate_fix_diff
# ---------------------------------------------------------------------------

class TestGenerateFixDiff:
    FINDING = {
        "rule": "Hardcoded Secret",
        "severity": "CRITICAL",
        "file": "app.py",
        "line": 3,
        "message": "Hardcoded password detected",
        "fix_hint": "Move to environment variables.",
        "code_snippet": 'password = "hunter2"',
    }

    FILE_CONTENT = '''import os
from flask import Flask
password = "hunter2"
app = Flask(__name__)
'''

    def test_graceful_without_api_key(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        result = generate_fix_diff(self.FINDING, self.FILE_CONTENT)
        assert result["rule"] == "Hardcoded Secret"
        assert result["confidence"] == "high"
        assert result["fallback_hint"] == "Move to environment variables."
        assert "GROQ_API_KEY" in result["explanation"]
        assert result["diff"] == ""  # no diff without API key

    def test_returns_correct_structure(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        result = generate_fix_diff(self.FINDING, self.FILE_CONTENT)
        required_keys = {"diff", "explanation", "confidence", "rule", "line", "fallback_hint"}
        assert required_keys.issubset(result.keys())

    def test_with_mocked_groq(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "test-key")

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '''```diff
--- a/app.py
+++ b/app.py
@@ -3 +3 @@
-password = "hunter2"
+password = os.environ.get("PASSWORD")
```

Replaced hardcoded password with environment variable lookup.'''

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch("vibesec.fixgen.Groq", return_value=mock_client):
            result = generate_fix_diff(self.FINDING, self.FILE_CONTENT)

        assert result["diff"] != ""
        assert "password" in result["diff"]
        assert "os.environ" in result["diff"]
        assert result["rule"] == "Hardcoded Secret"
        assert result["line"] == 3

    def test_handles_groq_auth_error(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "bad-key")

        import groq as groq_module

        with patch("vibesec.fixgen.Groq") as MockGroq:
            mock_client = MagicMock()
            mock_client.chat.completions.create.side_effect = groq_module.AuthenticationError(
                message="Invalid API key",
                response=MagicMock(status_code=401),
                body=None,
            )
            MockGroq.return_value = mock_client

            result = generate_fix_diff(self.FINDING, self.FILE_CONTENT)

        assert result["diff"] == ""
        assert "Invalid" in result["explanation"] or "fix hint" in result["explanation"].lower()

    def test_handles_groq_rate_limit(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "test-key")

        import groq as groq_module

        with patch("vibesec.fixgen.Groq") as MockGroq:
            mock_client = MagicMock()
            mock_client.chat.completions.create.side_effect = groq_module.RateLimitError(
                message="Rate limited",
                response=MagicMock(status_code=429),
                body=None,
            )
            MockGroq.return_value = mock_client

            result = generate_fix_diff(self.FINDING, self.FILE_CONTENT)

        assert result["diff"] == ""
        assert "rate limit" in result["explanation"].lower() or "static fix" in result["explanation"].lower()

    def test_no_file_content_uses_snippet(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        result = generate_fix_diff(self.FINDING, file_content="")
        # Should still work — uses code_snippet as fallback context
        assert result["rule"] == "Hardcoded Secret"

    def test_unknown_rule_gets_low_confidence(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        finding = dict(self.FINDING)
        finding["rule"] = "Unknown Future Rule"
        result = generate_fix_diff(finding)
        assert result["confidence"] == "low"


# ---------------------------------------------------------------------------
# Integration: template prompt quality
# ---------------------------------------------------------------------------

class TestPromptQuality:
    """Verify that templates produce meaningful, non-generic prompts."""

    def test_sql_injection_prompt_mentions_parameterized(self):
        t = get_template("SQL Injection Risk")
        assert "parameterized" in t["canonical_fix"]
        assert ".format()" in t["pitfalls"]

    def test_command_injection_prompt_mentions_shell_false(self):
        t = get_template("Command Injection")
        assert "shell=False" in t["canonical_fix"]
        assert "shlex" in t["pitfalls"]

    def test_secrets_prompt_mentions_env_var(self):
        t = get_template("Hardcoded Secret")
        assert "environment variable" in t["canonical_fix"]
        assert "config.py" in t["pitfalls"]

    def test_xss_prompt_mentions_dompurify(self):
        t = get_template("Unsafe HTML Injection (XSS)")
        assert "DOMPurify" in t["canonical_fix"]

    def test_path_traversal_mentions_realpath(self):
        t = get_template("Path Traversal")
        assert "realpath" in t["canonical_fix"]

    def test_ssrf_mentions_private_ip(self):
        t = get_template("Server-Side Request Forgery")
        assert "private" in t["canonical_fix"].lower() or "internal" in t["canonical_fix"].lower()
