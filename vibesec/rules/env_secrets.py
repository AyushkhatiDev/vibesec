import re

RULE_NAME = "Credentials in Environment File"
SEVERITY = "HIGH"

# Patterns for real credentials in .env files
PATTERNS = [
    # Database URLs with passwords
    (r"(DATABASE_URL|DB_URL)\s*=\s*\w+://[^:]+:[^@]{4,}@",
     "Database URL contains credentials — rotate if committed to git"),

    # Razorpay keys
    (r"RAZORPAY_KEY_SECRET\s*=\s*[a-zA-Z0-9]{20,}",
     "Razorpay secret key in environment file"),

    # Real Razorpay live/test key IDs
    (r"rzp_(live|test)_[a-zA-Z0-9]{14,}",
     "Razorpay API key detected"),

    # Payment platform API keys
    (r"PAYMENT_PLATFORM_API_KEY\s*=\s*[a-zA-Z0-9]{20,}",
     "Payment platform API key in environment file"),

    # Generic API secrets
    (r"(API_SECRET|APP_SECRET|CLIENT_SECRET)\s*=\s*[a-zA-Z0-9_\-]{16,}",
     "API secret key in environment file"),

    # reCAPTCHA secret
    (r"RECAPTCHA_SECRET_KEY\s*=\s*[a-zA-Z0-9_\-]{20,}",
     "reCAPTCHA secret key in environment file"),

    # Webhook secrets
    (r"WEBHOOK_SECRET\s*=\s*[a-zA-Z0-9_\-]{16,}",
     "Webhook secret in environment file"),
]

# These files should have real values — only flag if likely committed
ONLY_SCAN = {".env", ".env.local", ".env.production", ".env.prod"}


def check_env_secrets(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]

    # Only scan actual .env files not examples
    if filename not in ONLY_SCAN:
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": line_num,
                    "message": description,
                    "fix_hint": "Add .env to .gitignore immediately. Rotate all exposed credentials.",
                    "code_snippet": line.strip()[:80],
                })
                break

    return findings
