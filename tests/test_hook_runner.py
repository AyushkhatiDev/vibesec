"""Tests for vibesec.hook_runner — the enforcement hook engine."""

import json
import os
import sys
import tempfile
from unittest.mock import patch

import pytest

from vibesec.hook_runner import _resolve_input, _format_stderr_report, run_hook, run_batch


# ---------------------------------------------------------------------------
# _resolve_file_path
# ---------------------------------------------------------------------------

class TestResolveInput:
    def test_cli_argument_takes_priority(self):
        path, content = _resolve_input("/some/file.py")
        assert path == "/some/file.py"
        assert content is None

    def test_cli_argument_resolves_relative(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("x = 1")
        with patch("os.path.abspath", return_value=str(f)):
            path, content = _resolve_input("app.py")
        assert path == str(f)
        assert content is None

    def test_env_variable_file(self, monkeypatch, tmp_path):
        f = tmp_path / "env_file.py"
        f.write_text("x = 1")
        monkeypatch.setenv("FILE", str(f))
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            path, content = _resolve_input(None)
        assert path is not None
        assert path.endswith("env_file.py")
        assert content is None

    def test_env_variable_claude_tool_output_file(self, monkeypatch, tmp_path):
        f = tmp_path / "claude_out.py"
        f.write_text("x = 1")
        monkeypatch.setenv("CLAUDE_TOOL_OUTPUT_FILE", str(f))
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            path, content = _resolve_input(None)
        assert path is not None
        assert path.endswith("claude_out.py")
        assert content is None

    def test_no_input_returns_none(self, monkeypatch):
        monkeypatch.delenv("FILE", raising=False)
        monkeypatch.delenv("CLAUDE_TOOL_OUTPUT_FILE", raising=False)
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            path, content = _resolve_input(None)
        assert path is None
        assert content is None

    def test_stdin_json_extracts_content(self, monkeypatch):
        """When stdin JSON has a 'content' field, it should be returned alongside path."""
        payload = json.dumps({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/secret.py",
                "content": 'DATABASE_URL = "postgres://admin:pw@host/db"'
            }
        })
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            mock_stdin.read.return_value = payload
            path, content = _resolve_input(None)
        assert path is not None
        assert path.endswith("secret.py")
        assert content == 'DATABASE_URL = "postgres://admin:pw@host/db"'


# ---------------------------------------------------------------------------
# _format_stderr_report
# ---------------------------------------------------------------------------

class TestFormatStderrReport:
    def test_blocking_findings_shown(self):
        findings = [
            {
                "rule": "Hardcoded Secret",
                "severity": "CRITICAL",
                "line": 5,
                "message": "API key found",
                "fix_hint": "Use env vars",
            },
        ]
        report = _format_stderr_report(findings, "app.py", ["CRITICAL", "HIGH"])
        assert "BLOCKING" in report
        assert "Hardcoded Secret" in report
        assert "API key found" in report

    def test_advisory_findings_shown(self):
        findings = [
            {
                "rule": "CORS",
                "severity": "MEDIUM",
                "line": 10,
                "message": "Wildcard CORS",
                "fix_hint": "Restrict origins",
            },
        ]
        report = _format_stderr_report(findings, "app.py", ["CRITICAL", "HIGH"])
        assert "advisory" in report
        assert "CORS" in report
        assert "BLOCKING" not in report

    def test_mixed_findings(self):
        findings = [
            {
                "rule": "SQL Injection",
                "severity": "CRITICAL",
                "line": 3,
                "message": "Tainted SQL",
                "fix_hint": "Parameterize",
            },
            {
                "rule": "CORS",
                "severity": "MEDIUM",
                "line": 10,
                "message": "Wildcard",
                "fix_hint": "Restrict",
            },
        ]
        report = _format_stderr_report(findings, "app.py", ["CRITICAL", "HIGH"])
        assert "BLOCKING" in report
        assert "advisory" in report


# ---------------------------------------------------------------------------
# run_hook — exit code behavior
# ---------------------------------------------------------------------------

class TestRunHook:
    def test_clean_file_returns_0(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1\ny = 2\n")
        assert run_hook(str(f)) == 0

    def test_critical_finding_returns_2(self, tmp_path):
        f = tmp_path / "insecure.py"
        f.write_text('password = "supersecretpassword123"\n')
        result = run_hook(str(f))
        assert result == 2

    def test_medium_only_returns_0(self, tmp_path):
        """MEDIUM findings are advisory — should not block."""
        f = tmp_path / "mild.py"
        # dangerouslySetInnerHTML triggers MEDIUM XSS rule in .jsx/.tsx
        # For Python, we need a MEDIUM-only finding. Let's use eval in a
        # context that triggers only MEDIUM.
        # Actually, let's mock the rules to return a MEDIUM finding.
        with patch("vibesec.hook_runner._run_rules") as mock_rules:
            mock_rules.return_value = [
                {
                    "rule": "Test Rule",
                    "severity": "MEDIUM",
                    "file": str(f),
                    "line": 1,
                    "message": "Test finding",
                    "fix_hint": "Test fix",
                    "code_snippet": "x = 1",
                },
            ]
            f.write_text("x = 1\n")
            result = run_hook(str(f))
        assert result == 0

    def test_missing_file_returns_0(self):
        result = run_hook("/nonexistent/file.py")
        assert result == 0

    def test_binary_file_returns_0(self, tmp_path):
        f = tmp_path / "binary.pyc"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert run_hook(str(f)) == 0

    def test_disabled_via_config_returns_0(self, tmp_path):
        f = tmp_path / "insecure.py"
        f.write_text('SECRET_KEY = "hunter2"\n')
        hooks_config = {
            "block_on": ["CRITICAL", "HIGH"],
            "timeout": 30,
            "enabled": False,  # Kill switch
        }
        assert run_hook(str(f), hooks_config=hooks_config) == 0

    def test_custom_block_on_includes_medium(self, tmp_path):
        """When block_on includes MEDIUM, MEDIUM findings should block."""
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        with patch("vibesec.hook_runner._run_rules") as mock_rules:
            mock_rules.return_value = [
                {
                    "rule": "Test Rule",
                    "severity": "MEDIUM",
                    "file": str(f),
                    "line": 1,
                    "message": "Test",
                    "fix_hint": "Fix",
                    "code_snippet": "x",
                },
            ]
            hooks_config = {
                "block_on": ["CRITICAL", "HIGH", "MEDIUM"],
                "timeout": 30,
                "enabled": True,
            }
            result = run_hook(str(f), hooks_config=hooks_config)
        assert result == 2

    def test_stderr_output_on_findings(self, tmp_path, capsys):
        """Findings should produce output on stderr."""
        f = tmp_path / "secret.py"
        f.write_text('password = "supersecretpassword123"\n')
        run_hook(str(f))
        captured = capsys.readouterr()
        assert "VibeSec" in captured.err or "BLOCKING" in captured.err


# ---------------------------------------------------------------------------
# run_batch — PostToolBatch behavior
# ---------------------------------------------------------------------------

class TestRunBatch:
    def test_run_batch_empty_signals_returns_0(self, tmp_path):
        with patch("vibesec.hook_runner._signal_file_path") as mock_signal_path:
            signal_file = tmp_path / "test_signal.json"
            mock_signal_path.return_value = str(signal_file)
            assert run_batch() == 0

    def test_run_batch_with_signals_returns_2_and_clears(self, tmp_path, capsys):
        with patch("vibesec.hook_runner._signal_file_path") as mock_signal_path:
            signal_file = tmp_path / "test_signal.json"
            mock_signal_path.return_value = str(signal_file)
            
            # Write some dummy signals
            signals = [
                {
                    "file": "app.py",
                    "findings": [
                        {"rule": "Hardcoded Secret", "severity": "CRITICAL"}
                    ]
                }
            ]
            with open(signal_file, "w", encoding="utf-8") as f:
                json.dump(signals, f)
            
            assert signal_file.exists()
            
            # Running batch should return 2 (blocking)
            assert run_batch() == 2
            
            # Check stderr output
            captured = capsys.readouterr()
            assert "VibeSec PostToolBatch" in captured.err
            assert "1 blocking security issue(s)" in captured.err
            assert "app.py" in captured.err
            
            # Signal file should be cleared/removed
            assert not signal_file.exists()

    def test_run_hook_writes_signal_on_blocking(self, tmp_path):
        f = tmp_path / "secret.py"
        f.write_text('password = "supersecretpassword123"\n')
        
        with patch("vibesec.hook_runner._signal_file_path") as mock_signal_path:
            signal_file = tmp_path / "test_signal.json"
            mock_signal_path.return_value = str(signal_file)
            
            # Run hook on blocking file
            assert run_hook(str(f)) == 2
            
            # Signal file should be written with findings
            assert signal_file.exists()
            with open(signal_file, "r", encoding="utf-8") as sf:
                data = json.load(sf)
            
            assert len(data) == 1
            assert data[0]["file"] == str(f)
            assert len(data[0]["findings"]) > 0


class TestRunStaged:
    def test_run_staged_empty_staged_returns_0(self):
        from vibesec.hook_runner import run_staged
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            assert run_staged() == 0

    def test_run_staged_blocks_on_vulnerable_staged_file(self, tmp_path):
        from vibesec.hook_runner import run_staged
        vuln_file = tmp_path / "secret.py"
        vuln_file.write_text('api_key = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"')

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "secret.py\n"
            assert run_staged(project_dir=str(tmp_path)) == 2
