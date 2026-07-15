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

# Try to extract file path from tool_input using Python (no jq dependency)
FILE_PATH=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    ti = data.get('tool_input', {})
    path = ti.get('file_path') or ti.get('file') or ti.get('target_file') or ''
    print(path)
except Exception:
    print('')
" 2>/dev/null || echo "")

# If we couldn't extract a file path, allow the tool call to proceed
if [ -z "$FILE_PATH" ]; then
    exit 0
fi

# If the file doesn't exist on disk, nothing to scan
if [ ! -f "$FILE_PATH" ]; then
    exit 0
fi

# Run VibeSec hook runner — it handles severity filtering and exit codes
exec python3 -m vibesec.hook_runner --file "$FILE_PATH"
