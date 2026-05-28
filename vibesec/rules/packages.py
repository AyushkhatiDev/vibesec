import json
import re
from concurrent.futures import ThreadPoolExecutor

import requests

RULE_NAME = "Hallucinated Package"
SEVERITY = "HIGH"

# Known hallucinated package names LLMs commonly generate
KNOWN_HALLUCINATED = {
    "react-auth-handler",
    "node-security-utils",
    "next-auth-helpers",
}

_NPM_EXISTS_CACHE = {}
MAX_SUSPICIOUS_CHECKS = 20
BATCH_SIZE = 10


def check_npm_exists(package_name):
    """Check if package exists on npm registry."""
    if package_name in _NPM_EXISTS_CACHE:
        return _NPM_EXISTS_CACHE[package_name]
    try:
        url = f"https://registry.npmjs.org/{package_name}"
        response = requests.get(url, timeout=2)
        exists = response.status_code == 200
    except Exception:
        exists = True  # If we can't check, assume it exists (avoid false positives)
    _NPM_EXISTS_CACHE[package_name] = exists
    return exists


def batch_check_npm_exists(package_names):
    """Check npm existence in batches of 10, capped per scan."""
    results = {}
    limited = list(dict.fromkeys(package_names))[:MAX_SUSPICIOUS_CHECKS]
    for index in range(0, len(limited), BATCH_SIZE):
        batch = limited[index:index + BATCH_SIZE]
        with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            for package_name, exists in zip(batch, executor.map(check_npm_exists, batch)):
                results[package_name] = exists
    return results


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

    suspicious_packages = []

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
            suspicious_packages.append(package_name)

    registry_results = batch_check_npm_exists(suspicious_packages)
    for package_name, exists in registry_results.items():
        if not exists:
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
