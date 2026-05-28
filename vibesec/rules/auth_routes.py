import re

RULE_NAME = "Missing Route Authentication"
SEVERITY = "HIGH"

# Routes that look like admin or sensitive endpoints
SENSITIVE_ROUTE_PATTERNS = [
    r'@app\.route\s*\(\s*["\'][^"\']*admin[^"\']*["\']',
    r'@app\.route\s*\(\s*["\'][^"\']*delete[^"\']*["\']',
    r'@app\.route\s*\(\s*["\'][^"\']*\/api\/user[^"\']*["\']',
    r'router\.(post|put|delete|patch)\s*\(\s*["\'][^"\']*admin[^"\']*["\']',
    r'app\.(post|put|delete|patch)\s*\(\s*["\'][^"\']*admin[^"\']*["\']',
]

# Auth decorators/middleware that make a route safe
AUTH_INDICATORS = [
    "login_required",
    "jwt_required",
    "auth_required",
    "verify_token",
    "authenticate",
    "authorization",
    "requireAuth",
    "withAuth",
    "authMiddleware",
    "auth_middleware",
    "isAuthenticated",
    "checkAuth",
    "session['user",
    "session.get('user",
    "session.user",
    "current_user",
    "g.user",
    "getServerSession",
    "currentUser",
    "verifyJWT",
]


def check_auth_routes(file_path, content):
    findings = []

    ext = file_path.split(".")[-1].lower()
    if ext not in {"py", "js", "ts", "jsx", "tsx"}:
        return findings

    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        for pattern in SENSITIVE_ROUTE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Check surrounding lines for route-level or router-level auth.
                start = max(0, line_num - 20)
                end = min(len(lines), line_num + 20)
                surrounding = "\n".join(lines[start:end]).lower()

                has_auth = any(
                    indicator.lower() in surrounding
                    for indicator in AUTH_INDICATORS
                )

                if not has_auth:
                    findings.append({
                        "rule": RULE_NAME,
                        "severity": SEVERITY,
                        "file": file_path,
                        "line": line_num,
                        "message": "Sensitive route defined without visible auth middleware",
                        "fix_hint": "Add authentication decorator or middleware before this route handler.",
                        "code_snippet": line.strip()[:80],
                    })
                break

    return findings
