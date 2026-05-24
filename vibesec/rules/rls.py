import re

RULE_NAME = "Supabase RLS Disabled"
SEVERITY = "CRITICAL"

PATTERNS = [
    (r'alter\s+table\s+\w+\s+disable\s+row\s+level\s+security',
     "RLS explicitly disabled on table"),
    (r'row\s+level\s+security.*disabled',
     "Row level security disabled"),
    (r'\.from\(["\'](\w+)["\']\)\s*\.select',
     "Supabase query — verify RLS is enabled on this table"),
]

SKIP_FILES = {"README.md", "readme.md"}


def check_rls(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    if filename in SKIP_FILES:
        return findings

    ext = file_path.split(".")[-1].lower()

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("--") or stripped.startswith("#"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # For .select queries, only flag in non-SQL files
                # SQL files legitimately define RLS
                if "select" in pattern and ext == "sql":
                    continue

                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": line_num,
                    "message": description,
                    "fix_hint": "Enable RLS: ALTER TABLE table_name ENABLE ROW LEVEL SECURITY; then add policies.",
                    "code_snippet": line.strip()[:80],
                })
                break

    return findings
