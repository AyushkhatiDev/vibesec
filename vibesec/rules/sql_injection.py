import re

RULE_NAME = "SQL Injection Risk"
SEVERITY = "CRITICAL"

PATTERNS = [
    # String concatenation in SQL
    (r"(execute|cursor\.execute)\s*\(\s*[\"\'][^\"\']*\'\s*\+",
     "SQL query built with string concatenation — injection risk"),

    (r"(execute|cursor\.execute)\s*\(\s*f[\"\'].*\{",
     "SQL query built with f-string — injection risk"),

    (r"(execute|cursor\.execute)\s*\(\s*[\"\'][^\"\']*%\s*[^,)]+\)",
     "SQL query using % formatting — use parameterized queries instead"),

    # Raw SQL with user input
    (r"db\.engine\.execute\s*\(\s*[\"\'][^\"\']*\+",
     "Raw SQL execution with string concatenation"),

    (r"text\s*\(\s*f[\"\'].*SELECT.*\{",
     "SQLAlchemy text() with f-string interpolation — injection risk"),

    # Filter with string format
    (r"filter\s*\(\s*.*format\s*\(",
     "ORM filter using string format — use parameterized queries"),
]

SKIP_FILES = {"README.md", "readme.md"}


def check_sql_injection(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    if filename in SKIP_FILES:
        return findings

    ext = file_path.split(".")[-1].lower()
    if ext not in {"py"}:
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": line_num,
                    "message": description,
                    "fix_hint": "Use parameterized queries: db.execute(query, {'param': value}) never string concatenation.",
                    "code_snippet": line.strip()[:80],
                })
                break

    return findings
