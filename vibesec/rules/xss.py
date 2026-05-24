import re

RULE_NAME = "Unsafe HTML Injection (XSS)"
SEVERITY = "MEDIUM"

PATTERNS = [
    (r'dangerouslySetInnerHTML\s*=\s*\{\s*\{',
     "dangerouslySetInnerHTML used — potential XSS vulnerability"),
    (r'dangerouslySetInnerHTML.*\$\{',
     "dangerouslySetInnerHTML with template literal — XSS risk"),
    (r'dangerouslySetInnerHTML.*props\.',
     "dangerouslySetInnerHTML with props value — XSS risk"),
    (r'dangerouslySetInnerHTML.*state\.',
     "dangerouslySetInnerHTML with state value — XSS risk"),
    (r'innerHTML\s*=\s*[^"\'`][^\n]*\+',
     "innerHTML set with concatenated value — XSS risk"),
    (r'document\.write\s*\(',
     "document.write used — XSS risk"),
    (r'eval\s*\(\s*[^"\'`]',
     "eval() called with dynamic value — code injection risk"),
]

SKIP_FILES = {"README.md", "readme.md"}


def check_xss(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    if filename in SKIP_FILES:
        return findings

    ext = file_path.split(".")[-1].lower()
    if ext not in {"js", "ts", "jsx", "tsx"}:
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": line_num,
                    "message": description,
                    "fix_hint": "Sanitize HTML with DOMPurify before rendering. Avoid dangerouslySetInnerHTML with user input.",
                    "code_snippet": line.strip()[:80],
                })
                break

    return findings