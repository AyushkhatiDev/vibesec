import re

RULE_NAME = "Unsafe JWT Handling"
SEVERITY = "HIGH"

PATTERNS = [
    (r'jwt\.decode\s*\([^)]*algorithms\s*=\s*\[["\']none["\']\]',
     "JWT accepts 'none' algorithm — critical auth bypass"),
    (r'verify\s*=\s*False',
     "JWT verification explicitly disabled"),
    (r'localStorage\.setItem\s*\([^)]*token',
     "JWT stored in localStorage — vulnerable to XSS theft"),
    (r'sessionStorage\.setItem\s*\([^)]*token',
     "JWT stored in sessionStorage — vulnerable to XSS theft"),
    (r'algorithm.*none',
     "JWT 'none' algorithm detected"),
]

SKIP_FILES = {"README.md", "readme.md"}


def check_jwt(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    if filename in SKIP_FILES:
        return findings

    ext = file_path.split(".")[-1].lower()
    if ext not in {"py", "js", "ts", "jsx", "tsx"}:
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": line_num,
                    "message": description,
                    "fix_hint": "Always verify JWT signature. Use httpOnly cookies instead of localStorage.",
                    "code_snippet": line.strip()[:80],
                })
                break

    return findings