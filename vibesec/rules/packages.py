import json
import re
import requests

RULE_NAME = "Hallucinated Package"
SEVERITY = "HIGH"

# Known hallucinated package names LLMs commonly generate
KNOWN_HALLUCINATED = {
    "react-auth-handler",
    "supabase-helpers",
    "express-middleware-auth",
    "nextjs-utils",
    "react-secure-storage",
    "express-auth-jwt",
    "node-security-utils",
    "react-api-handler",
    "next-auth-helpers",
    "prisma-utils",
}


def check_npm_exists(package_name):
    """Check if package exists on npm registry."""
    try:
        url = f"https://registry.npmjs.org/{package_name}"
        response = requests.get(url, timeout=3)
        return response.status_code == 200
    except Exception:
        return True  # If we can't check, assume it exists (avoid false positives)


def check_packages(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]

    if filename != "package.json":
        return findings

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return findings

    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for package_name in all_deps:
        # First check known hallucinated list (fast, no API call)
        if package_name.lower() in KNOWN_HALLUCINATED:
            findings.append({
                "rule": RULE_NAME,
                "severity": SEVERITY,
                "file": file_path,
                "line": "N/A",
                "message": f"'{package_name}' is a known hallucinated package name",
                "fix_hint": f"Remove '{package_name}' — this package does not exist. Find the correct package on npmjs.com.",
                "code_snippet": package_name,
            })
            continue

        # Check for suspicious patterns
        suspicious = (
            re.search(r'(helper|util|handler|wrapper)s?$', package_name, re.I)
            and not package_name.startswith("@")
            and len(package_name) > 15
        )

        if suspicious:
            if not check_npm_exists(package_name):
                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": "N/A",
                    "message": f"'{package_name}' does not exist on npm registry",
                    "fix_hint": "This package may be hallucinated by an AI tool. Verify on npmjs.com before using.",
                    "code_snippet": package_name,
                })

    return findings