import re

RULE_NAME = "Client-Side Role Trust"
SEVERITY = "HIGH"

PATTERNS = [
    (r'localStorage\.getItem\s*\([^)]*role',
     "Role read from localStorage — can be tampered by user"),
    (r'localStorage\.getItem\s*\([^)]*admin',
     "Admin flag read from localStorage — can be tampered by user"),
    (r'localStorage\.getItem\s*\([^)]*permission',
     "Permission read from localStorage — can be tampered by user"),
    (r'if\s*\([^)]*localStorage[^)]*admin',
     "Admin check using localStorage value — client-side trust"),
    (r'params\.(role|admin|isAdmin|permission)\s*===',
     "Role/permission check using URL params — can be manipulated"),
    (r'searchParams\.(get|role|admin)',
     "Role read from URL search params — easily manipulated"),
    (r'isAdmin\s*=\s*.*localStorage',
     "isAdmin derived from localStorage — insecure"),
    (r'userRole\s*=\s*.*localStorage',
     "userRole derived from localStorage — insecure"),
]

SKIP_FILES = {"README.md", "readme.md"}


def check_roles(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    if filename in SKIP_FILES:
        return findings

    ext = file_path.split(".")[-1].lower()
    if ext not in {"js", "ts", "jsx", "tsx", "py"}:
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": line_num,
                    "message": description,
                    "fix_hint": "Always verify roles server-side. Never trust client-provided role values.",
                    "code_snippet": line.strip()[:80],
                })
                break

    return findings