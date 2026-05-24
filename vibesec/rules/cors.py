import re

RULE_NAME = "Permissive CORS Configuration"
SEVERITY = "MEDIUM"

PATTERNS = [
    (r'origin\s*:\s*["\']?\*["\']?',
     "CORS wildcard origin — any domain can make requests"),
    (r'Access-Control-Allow-Origin.*\*',
     "CORS wildcard in response header"),
    (r'cors\(\s*\)',
     "CORS enabled with no configuration — defaults to wildcard"),
    (r'allowedOrigins\s*[:=]\s*\[?\s*["\']?\*',
     "CORS allowed origins set to wildcard"),
    (r'credentials.*true.*\*|\*.*credentials.*true',
     "CORS wildcard with credentials — critical misconfiguration"),
]

SAFE_INDICATORS = [
    "process.env",
    "ALLOWED_ORIGINS",
    "whitelist",
    "allowlist",
    "origins.includes",
    "origin ===",
]

SKIP_FILES = {"README.md", "readme.md"}


def check_cors(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    if filename in SKIP_FILES:
        return findings

    ext = file_path.split(".")[-1].lower()
    if ext not in {"py", "js", "ts", "jsx", "tsx"}:
        return findings

    if "cors" not in content.lower() and "origin" not in content.lower():
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                start = max(0, line_num - 5)
                end = min(len(lines), line_num + 5)
                surrounding = "\n".join(lines[start:end])

                is_safe = any(
                    indicator in surrounding
                    for indicator in SAFE_INDICATORS
                )

                if not is_safe:
                    findings.append({
                        "rule": RULE_NAME,
                        "severity": SEVERITY,
                        "file": file_path,
                        "line": line_num,
                        "message": description,
                        "fix_hint": "Specify exact allowed origins. Never use wildcard CORS with credentials enabled.",
                        "code_snippet": line.strip()[:80],
                    })
                break

    return findings