"""
Tests for vibesec.sarif_reporter.

Validates SARIF 2.1.0 document structure, rule mappings, severity
conversions, relative path handling, snippet inclusion, and file output.
"""

import json
import os
import tempfile

import pytest

from vibesec.sarif_reporter import (
    RULES,
    generate_sarif,
    write_sarif,
    _severity_to_sarif_level,
    _to_relative_uri,
)
import vibesec


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _make_finding(**overrides):
    """Create a minimal VibeSec finding dict with sensible defaults."""
    base = {
        "rule": "Hardcoded Secret",
        "severity": "CRITICAL",
        "file": "/project/src/config.py",
        "line": 12,
        "message": "Hardcoded API key detected in source code",
        "fix_hint": "Move to environment variables.",
        "code_snippet": 'api_key = "sk-abc123..."',
    }
    base.update(overrides)
    return base


# ── Schema & version ────────────────────────────────────────────────────────

def test_sarif_schema_and_version():
    sarif = generate_sarif([], scan_root="/project")
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"


def test_sarif_empty_findings():
    sarif = generate_sarif([], scan_root="/project")
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


# ── Tool metadata ───────────────────────────────────────────────────────────

def test_sarif_tool_metadata():
    sarif = generate_sarif([_make_finding()], scan_root="/project")
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "VibeSec"
    assert driver["version"] == vibesec.__version__
    assert driver["informationUri"] == "https://github.com/AyushkhatiDev/vibesec"


# ── Rules array ─────────────────────────────────────────────────────────────

def test_sarif_rules_populated():
    findings = [
        _make_finding(rule="Hardcoded Secret"),
        _make_finding(rule="SQL Injection Risk", severity="CRITICAL"),
    ]
    sarif = generate_sarif(findings, scan_root="/project")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "VS001" in rule_ids
    assert "VS003" in rule_ids
    assert len(rules) == 2


def test_sarif_rules_have_descriptions():
    sarif = generate_sarif([_make_finding()], scan_root="/project")
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "shortDescription" in rule
    assert "text" in rule["shortDescription"]
    assert "fullDescription" in rule
    assert "text" in rule["fullDescription"]
    assert "helpUri" in rule


# ── Single finding ──────────────────────────────────────────────────────────

def test_sarif_single_finding():
    findings = [_make_finding()]
    sarif = generate_sarif(findings, scan_root="/project")
    results = sarif["runs"][0]["results"]
    assert len(results) == 1

    result = results[0]
    assert result["ruleId"] == "VS001"
    assert result["level"] == "error"
    assert "Hardcoded API key detected in source code" in result["message"]["text"]

    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/config.py"
    assert loc["region"]["startLine"] == 12


# ── Multiple findings ───────────────────────────────────────────────────────

def test_sarif_multiple_findings():
    findings = [
        _make_finding(rule="Hardcoded Secret", file="/project/a.py", line=1),
        _make_finding(
            rule="Permissive CORS Configuration",
            severity="MEDIUM",
            file="/project/b.js",
            line=5,
            message="Wildcard CORS origin",
        ),
        _make_finding(rule="Hardcoded Secret", file="/project/c.py", line=10),
    ]
    sarif = generate_sarif(findings, scan_root="/project")
    results = sarif["runs"][0]["results"]
    assert len(results) == 3

    # Two distinct rules
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2


# ── Severity mapping ────────────────────────────────────────────────────────

def test_sarif_severity_mapping():
    assert _severity_to_sarif_level("CRITICAL") == "error"
    assert _severity_to_sarif_level("HIGH") == "error"
    assert _severity_to_sarif_level("MEDIUM") == "warning"
    assert _severity_to_sarif_level("LOW") == "note"
    # Case-insensitive
    assert _severity_to_sarif_level("critical") == "error"
    assert _severity_to_sarif_level("high") == "error"


def test_sarif_severity_unknown_defaults_to_note():
    assert _severity_to_sarif_level("UNKNOWN") == "note"
    assert _severity_to_sarif_level("") == "note"


def test_sarif_medium_finding_has_warning_level():
    findings = [
        _make_finding(
            rule="Unsafe HTML Injection (XSS)",
            severity="MEDIUM",
            message="dangerouslySetInnerHTML used",
        )
    ]
    sarif = generate_sarif(findings, scan_root="/project")
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


# ── File path handling ──────────────────────────────────────────────────────

def test_sarif_file_path_relative():
    findings = [_make_finding(file="/project/src/deep/nested/file.py")]
    sarif = generate_sarif(findings, scan_root="/project")
    uri = sarif["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["artifactLocation"]["uri"]
    assert uri == "src/deep/nested/file.py"
    assert not uri.startswith("/")


def test_to_relative_uri_basic():
    assert _to_relative_uri("/project/src/a.py", "/project") == "src/a.py"
    assert _to_relative_uri("/project/a.py", "/project") == "a.py"


def test_sarif_uri_base_id():
    """SARIF results should use %SRCROOT% as the uriBaseId."""
    sarif = generate_sarif([_make_finding()], scan_root="/project")
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"


# ── Unknown rule fallback ───────────────────────────────────────────────────

def test_sarif_unknown_rule_fallback():
    findings = [
        _make_finding(rule="Some Future Rule", severity="LOW", message="new check")
    ]
    sarif = generate_sarif(findings, scan_root="/project")
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "VS000"
    assert result["level"] == "note"

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "VS000"
    assert rules[0]["name"] == "Some Future Rule"


# ── Snippet inclusion ───────────────────────────────────────────────────────

def test_sarif_snippet_included():
    findings = [_make_finding(code_snippet='api_key = "sk-abc123..."')]
    sarif = generate_sarif(findings, scan_root="/project")
    region = sarif["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["region"]
    assert "snippet" in region
    assert region["snippet"]["text"] == 'api_key = "sk-abc123..."'


def test_sarif_no_snippet_when_missing():
    findings = [_make_finding()]
    del findings[0]["code_snippet"]
    sarif = generate_sarif(findings, scan_root="/project")
    region = sarif["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["region"]
    assert "snippet" not in region


# ── Fix hint as SARIF fix ───────────────────────────────────────────────────

def test_sarif_fix_hint_in_message():
    findings = [_make_finding(fix_hint="Use env variables.")]
    sarif = generate_sarif(findings, scan_root="/project")
    result = sarif["runs"][0]["results"][0]
    # Fix hint is appended to message text, not in a separate fixes field
    assert "Fix: Use env variables." in result["message"]["text"]
    assert "fixes" not in result


def test_sarif_line_none_defaults_to_1():
    """Findings with line=None should get startLine=1, not None."""
    findings = [_make_finding(line=None)]
    sarif = generate_sarif(findings, scan_root="/project")
    start_line = sarif["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["region"]["startLine"]
    assert start_line == 1
    assert isinstance(start_line, int)


def test_sarif_line_string_defaults_to_1():
    """Findings with line as a string should get startLine=1."""
    findings = [_make_finding(line="N/A")]
    sarif = generate_sarif(findings, scan_root="/project")
    start_line = sarif["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["region"]["startLine"]
    assert start_line == 1
    assert isinstance(start_line, int)


# ── File I/O ────────────────────────────────────────────────────────────────

def test_write_sarif_creates_file():
    findings = [_make_finding()]
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "results.sarif")
        write_sarif(findings, output_path, scan_root="/project")

        assert os.path.exists(output_path)

        with open(output_path, "r") as f:
            data = json.load(f)

        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1


def test_write_sarif_creates_parent_dirs():
    findings = [_make_finding()]
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "sub", "dir", "results.sarif")
        write_sarif(findings, output_path, scan_root="/project")
        assert os.path.exists(output_path)


# ── Rule registry completeness ──────────────────────────────────────────────

def test_all_rules_have_required_fields():
    """Every rule in the registry must have id, descriptions, level, helpUri."""
    for name, meta in RULES.items():
        assert "id" in meta, f"Rule '{name}' missing 'id'"
        assert "shortDescription" in meta, f"Rule '{name}' missing 'shortDescription'"
        assert "fullDescription" in meta, f"Rule '{name}' missing 'fullDescription'"
        assert "defaultLevel" in meta, f"Rule '{name}' missing 'defaultLevel'"
        assert "helpUri" in meta, f"Rule '{name}' missing 'helpUri'"
        assert meta["defaultLevel"] in (
            "error", "warning", "note"
        ), f"Rule '{name}' has invalid level '{meta['defaultLevel']}'"


def test_rule_ids_are_unique():
    ids = [meta["id"] for meta in RULES.values()]
    assert len(ids) == len(set(ids)), "Duplicate rule IDs found"


def test_rule_registry_has_13_rules():
    assert len(RULES) == 13
