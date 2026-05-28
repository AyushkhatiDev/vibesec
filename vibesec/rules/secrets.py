import re

RULE_NAME = "Hardcoded Secret"
SEVERITY = "CRITICAL"

# Patterns that indicate hardcoded secrets
PATTERNS = [
    (r'api_key\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "Hardcoded API key"),
    (r'api_secret\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "Hardcoded API secret"),
    (r'password\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded password"),
    (r'secret_key\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret key"),
    (r'sk-[a-zA-Z0-9]{48}', "OpenAI API key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub personal access token"),
    (r'SUPABASE_SERVICE_KEY\s*=\s*["\'][^"\']+["\']', "Supabase service key exposed"),
    (r'SUPABASE_SECRET\s*=\s*["\'][^"\']+["\']', "Supabase secret exposed"),
    (r'stripe[_\s]secret\s*=\s*["\'][^"\']+["\']', "Stripe secret key"),
    (r'sk_live_[a-zA-Z0-9]{24,}', "Stripe live secret key"),
    (r'AUTH_SECRET\s*=\s*["\'][^"\']{8,}["\']', "Auth secret hardcoded"),
    (r'DATABASE_URL\s*=\s*["\']postgresql://[^"\']+["\']', "Database URL with credentials"),
]

# Files to skip — these are expected to have these patterns
SKIP_FILES = {
    ".env.example", ".env.sample", ".env.template",
    "README.md", "readme.md", ".gitignore"
}

PLACEHOLDER_VALUES = {
    "your-key-here",
    "your-secret-here",
    "changeme",
    "placeholder",
    "example",
    "replace-me",
    "xxx",
    "yyy",
}


def check_secrets(file_path, content):
    findings = []

    # Skip example/template files
    filename = file_path.split("/")[-1].split("\\")[-1]
    normalized_path = file_path.replace("\\", "/")
    if (
        filename in SKIP_FILES
        or filename.startswith("test_")
        or normalized_path.startswith("tests/")
        or "/tests/" in normalized_path
    ):
        return findings

    # Skip .env files that are in .gitignore — but still flag if exposed
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                lower_line = line.lower()
                if any(value in lower_line for value in PLACEHOLDER_VALUES):
                    continue
                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": line_num,
                    "message": f"{description} detected in source code",
                    "fix_hint": "Move to environment variables. Never commit secrets to git.",
                    "code_snippet": line.strip()[:80],
                })
                break  # One finding per line is enough

    return findings
