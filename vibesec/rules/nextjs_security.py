import re

from vibesec.rules.common import JS_EXTENSIONS, finding, filename, is_comment, normalized_path, should_skip_file

RULE_NAME = "Next.js Security Issue"


def _is_next_api(file_path):
    path = normalized_path(file_path)
    return "/pages/api/" in path or "/app/api/" in path or path.startswith("pages/api/") or path.startswith("app/api/")


def check_nextjs_security(file_path, content):
    if should_skip_file(file_path, JS_EXTENSIONS):
        return []

    findings = []
    lines = content.splitlines()
    name = filename(file_path)

    if _is_next_api(file_path):
        for line_num, line in enumerate(lines, 1):
            if re.search(r"export\s+default\s+(async\s+)?function\s+handler\s*\(\s*req\s*,\s*res", line):
                window = "\n".join(lines[line_num - 1: line_num + 10])
                if not re.search(r"getServerSession|requireAuth|authenticate|auth|session|currentUser", window, re.I):
                    findings.append(finding(
                        RULE_NAME, "HIGH", file_path, line_num,
                        "Next.js API route handler lacks visible authentication check",
                        "Check authentication at the start of API handlers before processing requests.", line
                    ))
                break

    if '"use server"' in content or "'use server'" in content:
        if not re.search(r"\b(zod|yup|joi|validate|safeParse|parse|schema)\b", content):
            findings.append(finding(
                RULE_NAME, "HIGH", file_path, 1,
                "Server action lacks visible input validation",
                "Validate server action inputs with a schema before use.", lines[0] if lines else ""
            ))

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if is_comment(stripped):
            continue
        if re.search(r"return\s*\{\s*props\s*:\s*\{[^}]*\b(password|secret|key|token)\b", line, re.I):
            findings.append(finding(
                RULE_NAME, "MEDIUM", file_path, line_num,
                "getServerSideProps appears to return sensitive data to the client",
                "Return only non-sensitive props to browser-rendered pages.", line
            ))
        if re.search(r"NEXT_PUBLIC_[A-Z0-9_]*(SECRET|KEY|PASSWORD|TOKEN)", line):
            findings.append(finding(
                RULE_NAME, "MEDIUM", file_path, line_num,
                "NEXT_PUBLIC_ environment variable name suggests a public secret leak",
                "Never prefix secrets with NEXT_PUBLIC_; keep them server-only.", line
            ))

    if name in {"next.config.js", "next.config.ts"} and "headers()" not in content and "async headers" not in content:
        findings.append(finding(
            RULE_NAME, "MEDIUM", file_path, 1,
            "next.config.js lacks security headers() configuration",
            "Add a headers() config with CSP, HSTS, X-Frame-Options, and related headers.",
            lines[0] if lines else name,
        ))

    return findings
