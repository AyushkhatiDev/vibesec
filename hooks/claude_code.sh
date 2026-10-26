#!/usr/bin/env bash
# VibeSec PostToolUse Hook for Claude Code
# -----------------------------------------
# This script is invoked by Claude Code after every Write/Edit/MultiEdit
# tool call. It reads the tool context from stdin, extracts the file path,
# and runs VibeSec's security rules against it.
#
# Exit codes:
#   0  — clean or advisory-only findings
#   2  — blocking findings; Claude must fix issues before continuing
#
# Install:
#   vibesec hooks install --client claude-code
#
# Or manually add to .claude/settings.json:
#   {
#     "hooks": {
#       "PostToolUse": [{
#         "matcher": "Write|Edit|MultiEdit",
#         "hooks": [{
#           "type": "command",
#           "command": "/path/to/hooks/claude_code.sh",
#           "timeout": 30
#         }]
#       }]
#     }
#   }
set -euo pipefail

# Read stdin (Claude Code provides JSON with tool context)
INPUT=$(cat)

# If input is empty, allow to proceed
if [ -z "$INPUT" ]; then
    exit 0
fi

# Run VibeSec hook runner — passes JSON on stdin to preserve inline content
echo "$INPUT" | exec python3 -m vibesec.hook_runner
