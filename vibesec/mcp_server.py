"""
VibeSec MCP Server
-------------------
Exposes VibeSec's deterministic security analysis as MCP tools so AI
coding agents (Claude Code, Cursor, Windsurf, etc.) can call it mid-task
and fix issues in the same editing turn.

This calls the rule engine directly — no subprocess, no file walking,
no progress bars. Single-file analysis completes in milliseconds.

Install:
    pip install "mcp[cli]>=1.0"

Run (stdio transport — the standard for local MCP servers):
    python -m vibesec.mcp_server

Agent-side config (e.g. Claude Code .claude/mcp.json):
    {
      "mcpServers": {
        "vibesec": {
          "command": "python",
          "args": ["-m", "vibesec.mcp_server"]
        }
      }
    }
"""

import logging
import os
import tempfile
from typing import Any, Dict, List, Optional

try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    try:
        from mcp.server.mcpserver import MCPServer as FastMCP
    except (ImportError, ModuleNotFoundError):
        from mcp.server.fastmcp import FastMCP

from vibesec.rules import ALL_RULES
from vibesec.utils import read_file

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "vibesec",
    instructions=(
        "VibeSec is a deterministic security scanner for AI-generated code. "
        "Call check_code BEFORE declaring any code-writing task complete. "
        "If issues are found, fix them and re-check until clean=true."
    ),
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def _run_rules(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Run every VibeSec rule against (file_path, content).

    This is the same thing Scanner.scan_file does internally, minus
    the threading / progress-bar / file-walk machinery that only
    makes sense for CLI batch scans.
    """
    findings: List[Dict[str, Any]] = []
    for rule in ALL_RULES:
        try:
            results = rule(file_path, content)
            findings.extend(results)
        except Exception as exc:
            logger.warning("Rule %s failed on %s: %s", rule.__name__, file_path, exc)
    return findings


def _format_response(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Shape findings into the structured response the agent consumes."""
    issues = []
    for f in findings:
        issues.append(
            {
                "rule": f.get("rule", "unknown"),
                "severity": f.get("severity", "MEDIUM"),
                "file": f.get("file", ""),
                "line": f.get("line"),
                "message": f.get("message", ""),
                "fix_hint": f.get("fix_hint", ""),
                "code_snippet": f.get("code_snippet", ""),
            }
        )

    # Sort by severity so the agent sees critical items first.
    issues.sort(key=lambda i: SEVERITY_WEIGHT.get(i["severity"], 0), reverse=True)

    severity_counts: Dict[str, int] = {}
    risk_score = 0
    for issue in issues:
        sev = issue["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        risk_score += SEVERITY_WEIGHT.get(sev, 0)

    return {
        "clean": len(issues) == 0,
        "risk_score": risk_score,
        "summary": {"total": len(issues), **severity_counts},
        "issues": issues,
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@mcp.tool()
def check_code(
    code: str,
    filename: str = "untitled.py",
) -> Dict[str, Any]:
    """Run VibeSec security analysis on a code snippet.

    Call this BEFORE finishing any task that writes or modifies code.
    If the result has clean=false, fix every issue and re-run until
    clean=true.

    The filename hint controls which rules fire (e.g. Dockerfile rules
    only run on files named Dockerfile). Use the real target filename
    when possible.

    Args:
        code: The full source code to analyze.
        filename: Target filename (e.g. "app.py", "auth.ts",
            "Dockerfile"). Used to select the right rules — not
            required to exist on disk.

    Returns:
        {
            "clean": bool,          # true when no issues found
            "risk_score": int,      # weighted severity score
            "summary": {            # counts by severity
                "total": int,
                "CRITICAL": int,
                ...
            },
            "issues": [             # empty when clean
                {
                    "rule": str,        # e.g. "Hardcoded Secret"
                    "severity": str,    # CRITICAL / HIGH / MEDIUM / LOW
                    "file": str,
                    "line": int,
                    "message": str,     # what's wrong
                    "fix_hint": str,    # how to fix it
                    "code_snippet": str # the offending code
                }
            ]
        }
    """
    # Rules key off file_path for extension / naming checks, so we
    # create a synthetic but realistic path from the filename hint.
    safe_name = os.path.basename(filename) or "untitled.py"
    synthetic_path = os.path.join("/src", safe_name)
    findings = _run_rules(synthetic_path, code)
    return _format_response(findings)


@mcp.tool()
def check_file(file_path: str) -> Dict[str, Any]:
    """Run VibeSec security analysis on a file already on disk.

    Use check_code() when you already have the content in memory.
    Use this when you only have a path — e.g. scanning an existing
    file the agent didn't just write.

    Args:
        file_path: Absolute or workspace-relative path to the file.

    Returns:
        Same structure as check_code().
    """
    abs_path = os.path.abspath(file_path)
    if not os.path.isfile(abs_path):
        return {
            "clean": True,
            "risk_score": 0,
            "summary": {"total": 0},
            "issues": [],
            "error": f"File not found: {abs_path}",
        }

    content = read_file(abs_path)
    if not content:
        return {
            "clean": True,
            "risk_score": 0,
            "summary": {"total": 0},
            "issues": [],
            "error": f"Could not read file (binary or empty): {abs_path}",
        }

    findings = _run_rules(abs_path, content)
    return _format_response(findings)


@mcp.tool()
def check_diff(
    diff: str,
    filename: str = "untitled.py",
) -> Dict[str, Any]:
    """Run VibeSec analysis on only the added lines of a diff.

    Accepts a unified diff (the output of `git diff`). Only lines
    starting with '+' (excluding the +++ header) are analyzed, so
    existing code doesn't generate noise.

    Args:
        diff: A unified diff string.
        filename: The target filename, used for rule selection.

    Returns:
        Same structure as check_code().
    """
    added_lines: List[str] = []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])  # strip the leading '+'

    if not added_lines:
        return {
            "clean": True,
            "risk_score": 0,
            "summary": {"total": 0},
            "issues": [],
        }

    code = "\n".join(added_lines)
    safe_name = os.path.basename(filename) or "untitled.py"
    synthetic_path = os.path.join("/src", safe_name)
    findings = _run_rules(synthetic_path, code)
    return _format_response(findings)


@mcp.tool()
def list_rules() -> Dict[str, Any]:
    """List all security rules VibeSec checks for.

    Useful for understanding what the scanner covers, or for
    documenting which checks ran during a session.

    Returns:
        {"rules": [{"name": str, "module": str}, ...], "count": int}
    """
    rules = []
    for rule_fn in ALL_RULES:
        module = getattr(rule_fn, "__module__", "unknown")
        # Pull RULE_NAME / SEVERITY from the module if available
        import importlib

        mod = importlib.import_module(module)
        rules.append(
            {
                "name": getattr(mod, "RULE_NAME", rule_fn.__name__),
                "function": rule_fn.__name__,
                "module": module,
            }
        )
    return {"rules": rules, "count": len(rules)}


@mcp.tool()
def suggest_fix(
    code: str,
    issue: Dict[str, Any],
    filename: str = "untitled.py",
    context_lines: int = 15,
) -> Dict[str, Any]:
    """Generate an applicable code fix for a security issue.

    Call this after check_code() or check_file() finds issues.
    Pass the full source code and one issue from the issues array.
    Returns a unified diff you can apply directly, plus an explanation.

    Workflow:
        1. result = check_code(code, filename) → finds issues
        2. fix = suggest_fix(code, result["issues"][0], filename)
        3. Apply fix["diff"] to the code
        4. Verify with check_code(fixed_code, filename) → clean=true

    If GROQ_API_KEY is not set, returns a static fix hint instead
    of a generated diff. Set the env var for LLM-powered fixes.

    Args:
        code: The full source code of the file containing the issue.
        issue: One issue dict from check_code().issues[] — must have
            at minimum "rule", "line", and "message" fields.
        filename: Target filename (e.g. "app.py"). Used to detect
            the language and framework for fix generation.
        context_lines: Number of lines of context around the issue
            to include in the fix prompt (default 15).

    Returns:
        {
            "diff": str,           # unified diff to apply (empty if unavailable)
            "explanation": str,    # what the fix does and why
            "confidence": str,     # "high" / "medium" / "low"
            "rule": str,           # which rule this fixes
            "line": int,           # line number of the issue
            "fallback_hint": str,  # static fix_hint (always present)
        }
    """
    from vibesec.fixgen import generate_fix_diff

    # Normalize the issue — callers might pass partial dicts
    finding = {
        "rule": issue.get("rule", "unknown"),
        "severity": issue.get("severity", "HIGH"),
        "file": issue.get("file", filename),
        "line": issue.get("line", 0),
        "message": issue.get("message", ""),
        "fix_hint": issue.get("fix_hint", ""),
        "code_snippet": issue.get("code_snippet", ""),
    }

    return generate_fix_diff(
        finding=finding,
        file_content=code,
        surrounding_lines=context_lines,
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main():
    """Run the VibeSec MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

