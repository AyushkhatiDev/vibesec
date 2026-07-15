"""
VibeSec Hook Runner
-------------------
Shared enforcement engine invoked by PostToolUse hooks in Claude Code
and afterFileEdit hooks in Cursor.

This script runs VibeSec's security rules against a single file and
uses exit codes to enforce or advise:

    Exit 0  — clean or advisory-only findings (MEDIUM/LOW)
    Exit 2  — blocking findings (CRITICAL/HIGH by default)

The blocking threshold is configurable via vibesec.toml:

    [vibesec.hooks]
    block_on = ["CRITICAL", "HIGH"]

Usage:
    # Direct invocation with file path
    python -m vibesec.hook_runner --file path/to/file.py

    # Claude Code hook (reads stdin JSON with tool_input.file_path)
    echo '{"tool_input":{"file_path":"app.py"}}' | python -m vibesec.hook_runner

    # Cursor hook (file path via environment variable)
    FILE=app.py python -m vibesec.hook_runner
"""

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from vibesec.config import load_hooks_config
from vibesec.rules import ALL_RULES
from vibesec.utils import is_binary_file, read_file

logger = logging.getLogger(__name__)

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def _run_rules(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Run every VibeSec rule against a single file.

    Identical to the MCP server's _run_rules — same rule engine,
    same finding schema. Kept as a local function to avoid import
    coupling with the MCP server module.
    """
    findings: List[Dict[str, Any]] = []
    for rule in ALL_RULES:
        try:
            results = rule(file_path, content)
            findings.extend(results)
        except Exception as exc:
            logger.debug("Rule %s failed on %s: %s", rule.__name__, file_path, exc)
    return findings


def _resolve_input(
    cli_file: Optional[str],
) -> tuple:
    """Determine the file path and optional inline content to scan.

    Returns (file_path, inline_content) where inline_content may be None.

    When the stdin JSON includes a 'content' field (as Claude Code's Write
    hook does), we use that content directly rather than reading from disk.
    This means the scan runs on what Claude is *about* to write, even
    before the file is flushed to disk.

    Priority order:
    1. --file CLI argument  (no inline content)
    2. stdin JSON (Claude Code PostToolUse format)  (may have inline content)
    3. FILE or CLAUDE_TOOL_OUTPUT_FILE environment variable  (no inline content)
    """
    # 1. CLI argument
    if cli_file:
        return os.path.abspath(cli_file), None

    # 2. stdin JSON from Claude Code hook system
    if not sys.stdin.isatty():
        try:
            raw = sys.stdin.read()
            if raw.strip():
                data = json.loads(raw)
                tool_input = data.get("tool_input", {})
                path = (
                    tool_input.get("file_path")
                    or tool_input.get("file")
                    or tool_input.get("target_file")
                )
                if path:
                    abs_path = os.path.abspath(path)
                    # 'content' is present on Write/MultiEdit hooks — use it
                    # directly so we don't depend on the file being on disk yet.
                    inline_content = tool_input.get("content") or tool_input.get("new_content")
                    return abs_path, inline_content
        except (json.JSONDecodeError, AttributeError):
            pass

    # 3. Environment variables
    env_path = os.environ.get("CLAUDE_TOOL_OUTPUT_FILE") or os.environ.get("FILE")
    if env_path:
        return os.path.abspath(env_path), None

    return None, None


def _format_stderr_report(
    findings: List[Dict[str, Any]],
    file_path: str,
    block_on: List[str],
) -> str:
    """Format findings as concise, actionable text for agent stderr.

    Agents read stderr for feedback — keep it human-readable, not JSON.
    """
    lines = []
    blocking = []
    advisory = []

    for f in findings:
        sev = f.get("severity", "MEDIUM")
        entry = (
            f"  {sev}: {f.get('rule', 'unknown')} "
            f"(line {f.get('line', '?')})\n"
            f"    {f.get('message', '')}\n"
            f"    Fix: {f.get('fix_hint', 'No fix hint available')}"
        )
        if sev in block_on:
            blocking.append(entry)
        else:
            advisory.append(entry)

    lines.append(f"VibeSec security scan: {file_path}")
    lines.append("")

    if blocking:
        lines.append(f"🛑 {len(blocking)} BLOCKING issue(s) — fix before continuing:")
        lines.extend(blocking)
        lines.append("")

    if advisory:
        lines.append(f"⚠️  {len(advisory)} advisory issue(s):")
        lines.extend(advisory)
        lines.append("")

    return "\n".join(lines)


def _signal_file_path() -> str:
    """Return the path to the batch signal file.

    PostToolUse hooks write to this file when they find blocking issues.
    PostToolBatch hooks read it and clear it.
    """
    import tempfile

    return os.path.join(tempfile.gettempdir(), "vibesec_batch_signal.json")


def _write_signal(findings: List[Dict[str, Any]], file_path: str) -> None:
    """Append blocking findings to the batch signal file."""
    signal_path = _signal_file_path()
    existing = []
    if os.path.exists(signal_path):
        try:
            with open(signal_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = []

    existing.append({"file": file_path, "findings": findings})

    with open(signal_path, "w", encoding="utf-8") as f:
        json.dump(existing, f)


def _read_and_clear_signal() -> List[Dict[str, Any]]:
    """Read and delete the batch signal file. Returns the accumulated issues."""
    signal_path = _signal_file_path()
    if not os.path.exists(signal_path):
        return []

    try:
        with open(signal_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        data = []

    # Always clear the signal file after reading
    try:
        os.remove(signal_path)
    except OSError:
        pass

    return data


def run_hook(
    file_path: str,
    hooks_config: Optional[Dict] = None,
    inline_content: Optional[str] = None,
) -> int:
    """Run the enforcement hook against a single file.

    Args:
        file_path: Absolute path of the file being scanned (used for rule
            context and reporting even when content comes from inline_content).
        hooks_config: Optional pre-loaded hook config dict.
        inline_content: Code content passed directly from stdin JSON (the
            Write hook's 'content' field). When provided, this is used
            instead of reading from disk, so the scan works even before the
            file is flushed.

    Returns:
        0  — clean or advisory-only findings
        2  — blocking findings found (CRITICAL/HIGH by default)
    """
    if hooks_config is None:
        hooks_config = load_hooks_config(os.path.dirname(file_path))

    # Kill switch
    if not hooks_config.get("enabled", True):
        return 0

    block_on = [s.upper() for s in hooks_config.get("block_on", ["CRITICAL", "HIGH"])]

    if inline_content is not None:
        # Content came from stdin JSON — use it directly.
        # Skip the binary check; Claude Code won't send binary via 'content'.
        content = inline_content
    else:
        # Fall back to reading from disk (--file path, env var, etc.)
        if not os.path.isfile(file_path):
            return 0
        if is_binary_file(file_path):
            return 0
        content = read_file(file_path)

    if not content:
        return 0

    findings = _run_rules(file_path, content)
    if not findings:
        return 0

    # Partition into blocking vs advisory
    blocking_findings = [
        f for f in findings if f.get("severity", "MEDIUM") in block_on
    ]
    has_blocking = len(blocking_findings) > 0

    # Always report findings to stderr (agent reads this)
    report = _format_stderr_report(findings, file_path, block_on)
    sys.stderr.write(report)

    if has_blocking:
        # Write signal for PostToolBatch to pick up
        _write_signal(blocking_findings, file_path)
        return 2  # Claude Code shows stderr to Claude
    return 0


def run_batch() -> int:
    """Run the PostToolBatch enforcement check.

    Reads the signal file written by PostToolUse hooks. If any
    blocking issues were found during this batch, returns exit 2
    to stop the agentic loop.

    Returns:
        0  — no blocking issues in this batch
        2  — blocking issues found; stop the loop
    """
    signals = _read_and_clear_signal()
    if not signals:
        return 0

    # Summarize what was found across all files in this batch
    total_issues = sum(len(s.get("findings", [])) for s in signals)
    files = [s.get("file", "unknown") for s in signals]

    report = (
        f"VibeSec PostToolBatch: {total_issues} blocking security issue(s) "
        f"found across {len(files)} file(s).\n"
        f"Files: {', '.join(files)}\n"
        f"Claude must fix these issues before continuing.\n"
    )
    sys.stderr.write(report)
    return 2


def main():
    """CLI entrypoint for hook_runner."""
    parser = argparse.ArgumentParser(
        description="VibeSec enforcement hook runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--file",
        help="Path to the file to scan",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Run in PostToolBatch mode: check if any PostToolUse hooks "
        "found blocking issues and stop the loop if so.",
    )
    args = parser.parse_args()

    if args.batch:
        sys.exit(run_batch())

    file_path, inline_content = _resolve_input(args.file)
    if not file_path:
        # No file to scan — nothing to do
        sys.exit(0)

    exit_code = run_hook(file_path, inline_content=inline_content)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

