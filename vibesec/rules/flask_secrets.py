import re

RULE_NAME = "Insecure Flask Configuration"
SEVERITY = "HIGH"

PATTERNS = [
    # Fallback secret key pattern
    (r"SECRET_KEY\s*=\s*os\.environ\.get\([^)]+\)\s*or\s*[\"\'][^\"\']{1,50}[\"\']",
     "SECRET_KEY has hardcoded fallback — weak key used if env var missing"),

    # Hardcoded default in os.environ.get
    (r"os\.environ\.get\s*\([\"\'][^\"\']+[\"\']\s*,\s*[\"\'][a-zA-Z0-9_\-]{16,}[\"\']",
     "Real API key used as default value in os.environ.get()"),

    # Debug mode enabled
    (r"DEBUG\s*=\s*True",
     "DEBUG mode enabled — never run with DEBUG=True in production"),

    # Hardcoded secret key directly
    (r"SECRET_KEY\s*=\s*[\"\'][^\"\']{8,}[\"\']",
     "Flask SECRET_KEY hardcoded in source code"),

    # app.run with debug
    (r"app\.run\s*\([^)]*debug\s*=\s*True",
     "Flask app running with debug=True — exposes interactive debugger"),
]

SKIP_FILES = {"README.md", "readme.md", ".env.example"}


def check_flask_secrets(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    if filename in SKIP_FILES:
        return findings

    ext = file_path.split(".")[-1].lower()
    if ext not in {"py", "cfg", "ini"}:
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
                    "fix_hint": "Use strong random SECRET_KEY from environment. Never use fallbacks or hardcoded values.",
                    "code_snippet": line.strip()[:80],
                })
                break

    return findings
