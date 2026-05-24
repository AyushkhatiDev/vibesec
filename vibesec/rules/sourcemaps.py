import re
import os

RULE_NAME = "Source Map Exposure"
SEVERITY = "HIGH"

PATTERNS = [
    (r'["\']?sourceMap["\']?\s*[:=]\s*true', "Source maps enabled in build config"),
    (r'GENERATE_SOURCEMAP\s*=\s*true', "Create React App source maps enabled"),
    (r'devtool\s*:\s*["\']source-map["\']', "Webpack source-map devtool enabled"),
    (r'\"source-map\"', "Source map configuration detected"),
]


def check_sourcemaps(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    ext = file_path.split(".")[-1].lower()

    # Check .map files committed to repo
    if filename.endswith(".map"):
        # Check if it's in a build/dist directory
        if any(d in file_path for d in ["dist/", "build/", ".next/", "out/"]):
            findings.append({
                "rule": RULE_NAME,
                "severity": SEVERITY,
                "file": file_path,
                "line": "N/A",
                "message": "Source map file committed to repository — exposes full source code",
                "fix_hint": "Add *.map to .gitignore. Set sourceMap: false in production builds.",
                "code_snippet": filename,
            })
        return findings

    # Check build config files
    config_files = {
        "webpack.config.js", "webpack.config.ts",
        "next.config.js", "next.config.ts",
        "vite.config.js", "vite.config.ts",
        ".env", ".env.production", ".env.prod"
    }

    if filename not in config_files and ext not in {"json"}:
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "rule": RULE_NAME,
                    "severity": SEVERITY,
                    "file": file_path,
                    "line": line_num,
                    "message": description,
                    "fix_hint": "Set sourceMap: false in production. Use hidden-source-map if debugging is needed.",
                    "code_snippet": line.strip()[:80],
                })
                break

    return findings