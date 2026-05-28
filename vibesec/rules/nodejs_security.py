import re

from vibesec.rules.common import JS_EXTENSIONS, finding, is_comment, should_skip_file, surrounding_lines

RULE_NAME = "Node.js Security Misconfiguration"
SEVERITY = "MEDIUM"
FIX = "Add standard Express security middleware, validate parsed objects, harden cookies, and rate-limit public API routes."


def _is_server_file(file_path, content):
    name = file_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return (
        name in {"server.js", "server.ts", "app.js", "app.ts", "index.js", "index.ts"}
        or "express()" in content
        or "require('express')" in content
        or 'require("express")' in content
    )


def check_nodejs_security(file_path, content):
    if should_skip_file(file_path, JS_EXTENSIONS):
        return []

    findings = []
    lines = content.splitlines()
    has_helmet = re.search(r"\bhelmet\b", content) and re.search(r"\bapp\.use\s*\(\s*helmet\s*\(", content)
    has_rate_limit = "express-rate-limit" in content or "rateLimit(" in content

    if _is_server_file(file_path, content):
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if is_comment(stripped):
                continue
            if "express()" in line and not has_helmet:
                findings.append(finding(
                    RULE_NAME, SEVERITY, file_path, line_num,
                    "Express app appears to be missing helmet() security headers",
                    "Install helmet and call app.use(helmet()) before routes.", line
                ))
                break

        for line_num, line in enumerate(lines, 1):
            if re.search(r"\bapp\.(get|post|put|patch|delete)\s*\(\s*['\"]/api/", line) and not has_rate_limit:
                findings.append(finding(
                    RULE_NAME, SEVERITY, file_path, line_num,
                    "API route appears to be missing express-rate-limit middleware",
                    "Use express-rate-limit on public API routes.", line
                ))
                break

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if is_comment(stripped):
            continue
        context = surrounding_lines(lines, line_num, 3)
        if re.search(r"Object\.assign\s*\(\s*\{\s*\}\s*,\s*(req\.|userInput|input|body)", line):
            findings.append(finding(RULE_NAME, SEVERITY, file_path, line_num, "Object.assign() may copy attacker-controlled properties", FIX, line))
        elif re.search(r"\w+\s*=\s*JSON\.parse\s*\(\s*(req\.|userInput|input|body)", line):
            findings.append(finding(RULE_NAME, SEVERITY, file_path, line_num, "JSON.parse() result assigned directly from user input", FIX, line))
        elif re.search(r"\b(?:_|lodash)\.merge\s*\([^)]*(req\.|userInput|input|body)", line):
            findings.append(finding(RULE_NAME, SEVERITY, file_path, line_num, "lodash merge with user input may allow prototype pollution", FIX, line))
        elif "res.cookie(" in line:
            cookie_context = context.replace(" ", "")
            missing = [
                option for option in ("httpOnly:true", "secure:true", "sameSite")
                if option not in cookie_context
            ]
            if missing:
                findings.append(finding(
                    RULE_NAME, SEVERITY, file_path, line_num,
                    "res.cookie() is missing hardened cookie options",
                    "Set httpOnly: true, secure: true, and sameSite on sensitive cookies.", line
                ))

    return findings
