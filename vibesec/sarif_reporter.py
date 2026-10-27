"""
SARIF 2.1.0 reporter for VibeSec.

Converts VibeSec findings into the SARIF (Static Analysis Results Interchange
Format) standard so results appear natively in GitHub's Security tab as
inline code annotations.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import os

import vibesec

# ── Rule registry ────────────────────────────────────────────────────────────
# Maps VibeSec rule names → stable machine-readable IDs, default SARIF levels,
# and short + full descriptions used for the SARIF `rules` array.

RULES = {
    "Hardcoded Secret": {
        "id": "VS001",
        "shortDescription": "Hardcoded secret detected in source code.",
        "fullDescription": (
            "API keys, passwords, tokens, or database URLs are hardcoded "
            "in source files. Move them to environment variables and never "
            "commit secrets to version control."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-critical",
    },
    "Supabase RLS Disabled": {
        "id": "VS002",
        "shortDescription": "Supabase Row Level Security is disabled.",
        "fullDescription": (
            "Row Level Security is explicitly disabled on a table. Any "
            "authenticated user can read or modify all rows. Enable RLS "
            "and add user-isolation policies."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-critical",
    },
    "SQL Injection Risk": {
        "id": "VS003",
        "shortDescription": "User-controlled input reaches a SQL sink.",
        "fullDescription": (
            "Taint analysis detected user-controlled input flowing into a "
            "SQL query via string concatenation, f-strings, or format(). "
            "Use parameterized queries instead."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-critical",
    },
    "Missing Route Authentication": {
        "id": "VS004",
        "shortDescription": "Sensitive route lacks authentication.",
        "fullDescription": (
            "An admin or sensitive API route was scaffolded without "
            "authentication middleware or decorators."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Hallucinated Package": {
        "id": "VS005",
        "shortDescription": "npm package may not exist (hallucinated by AI).",
        "fullDescription": (
            "A dependency in package.json does not exist on the npm "
            "registry. AI tools sometimes generate plausible-sounding "
            "package names that are typosquatting attack surfaces."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Source Map Exposure": {
        "id": "VS006",
        "shortDescription": "Source maps exposed in production build.",
        "fullDescription": (
            "Build configuration exposes full source code via .map files "
            "in production, allowing attackers to read original source."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Unsafe JWT Handling": {
        "id": "VS007",
        "shortDescription": "JWT handled insecurely.",
        "fullDescription": (
            "JWT uses the 'none' algorithm, has verification disabled, "
            "or tokens are stored in localStorage/sessionStorage."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Client-Side Role Trust": {
        "id": "VS008",
        "shortDescription": "Authorization check uses client-controlled values.",
        "fullDescription": (
            "Admin or role checks rely on localStorage, sessionStorage, "
            "or URL parameters — values an attacker can freely modify."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Insecure Flask Configuration": {
        "id": "VS009",
        "shortDescription": "Flask app has insecure configuration.",
        "fullDescription": (
            "Flask DEBUG mode is enabled, SECRET_KEY is hardcoded, or a "
            "weak fallback key is used. These expose internals and make "
            "session forgery trivial."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Credentials in Environment File": {
        "id": "VS010",
        "shortDescription": "Real credentials found in a committed .env file.",
        "fullDescription": (
            "A .env file contains real API keys, database URLs, or "
            "webhook secrets. Add .env to .gitignore and use a secret "
            "manager or CI/CD environment variables."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Unsafe HTML Injection (XSS)": {
        "id": "VS011",
        "shortDescription": "Potential cross-site scripting (XSS) vector.",
        "fullDescription": (
            "Uses dangerouslySetInnerHTML, innerHTML with concatenation, "
            "document.write, or eval() with dynamic values — allowing "
            "attacker-controlled HTML/JS execution."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
    "Missing Webhook Verification": {
        "id": "VS012",
        "shortDescription": "Webhook endpoint lacks signature verification.",
        "fullDescription": (
            "A Stripe or GitHub webhook handler processes payloads "
            "without verifying the request signature, allowing forged "
            "webhook events."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
    "Permissive CORS Configuration": {
        "id": "VS013",
        "shortDescription": "CORS allows all origins or uses wildcard with credentials.",
        "fullDescription": (
            "CORS is configured with a wildcard origin or allows all "
            "origins with credentials enabled, weakening same-origin "
            "protections."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
    "Path Traversal": {
        "id": "VS014",
        "shortDescription": "User-controlled input flows into a filesystem path.",
        "fullDescription": (
            "Accessing filesystem paths using user-controlled input allows path "
            "traversal attacks. Validate, normalize, and restrict paths to an allowed base directory."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Command Injection": {
        "id": "VS015",
        "shortDescription": "User-controlled input reaches a system shell execution sink.",
        "fullDescription": (
            "Executing system commands with dynamic or user-controlled input can lead to "
            "remote code execution. Pass arguments as a list with shell=False or use safe APIs."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-critical",
    },
    "Server-Side Request Forgery": {
        "id": "VS016",
        "shortDescription": "Unvalidated URL fetched by the server (SSRF).",
        "fullDescription": (
            "Sending server-side HTTP requests to user-controlled URLs can expose internal "
            "services and cloud metadata. Allowlist destination hosts and reject private IP ranges."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Insecure Deserialization": {
        "id": "VS017",
        "shortDescription": "Untrusted data passed to unsafe deserialization functions.",
        "fullDescription": (
            "Deserializing untrusted data with pickle, yaml.load without SafeLoader, or eval() "
            "allows arbitrary code execution. Use safe formats like JSON or safe loaders."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Server-Side Template Injection": {
        "id": "VS018",
        "shortDescription": "User-controlled input rendered directly into a template.",
        "fullDescription": (
            "Rendering unescaped user input inside template engines allows "
            "Server-Side Template Injection and remote code execution."
        ),
        "defaultLevel": "error",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-high",
    },
    "Weak Cryptography": {
        "id": "VS019",
        "shortDescription": "Use of broken cryptographic primitives or insecure random generators.",
        "fullDescription": (
            "Broken algorithms like MD5/SHA1, weak ciphers, or standard pseudo-random number "
            "generators used for security tokens compromise cryptographic guarantees."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
    "Open Redirect": {
        "id": "VS020",
        "shortDescription": "Unvalidated redirect using user-controlled target.",
        "fullDescription": (
            "Redirecting users to untrusted URLs enables phishing and credential theft. "
            "Validate redirect targets against an allowlist of relative paths or known domains."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
    "Node.js Security Misconfiguration": {
        "id": "VS021",
        "shortDescription": "Insecure Node.js runtime or middleware configuration.",
        "fullDescription": (
            "Missing security headers, disabled certificate validation, or prototype "
            "pollution risks weaken Node.js runtime security."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
    "Next.js Security Issue": {
        "id": "VS022",
        "shortDescription": "Security misconfiguration or secret leak in Next.js application.",
        "fullDescription": (
            "Exposing server secrets via NEXT_PUBLIC_ prefixes, missing Server Actions "
            "authorization, or unsafe dangerouslySetInnerHTML in React/Next.js."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
    "Docker Security Issue": {
        "id": "VS023",
        "shortDescription": "Insecure Dockerfile configuration.",
        "fullDescription": (
            "Running containers as root, using outdated base images, or leaking build "
            "secrets in Dockerfile compromises container isolation."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
    "GitHub Actions Security Issue": {
        "id": "VS024",
        "shortDescription": "Security vulnerability or misconfiguration in GitHub Actions workflow.",
        "fullDescription": (
            "Unpinned third-party actions, untrusted PR checkout triggers (pull_request_target), "
            "or unescaped script injections allow workflow and repository compromise."
        ),
        "defaultLevel": "warning",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec#-medium",
    },
}

# ── Severity mapping ─────────────────────────────────────────────────────────

_SEVERITY_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_SEVERITY_SCORES = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.0",
}


def _severity_to_sarif_level(severity: str) -> str:
    """Map a VibeSec severity string to a SARIF level."""
    return _SEVERITY_TO_SARIF.get(severity.upper(), "note")


# ── Path helpers ─────────────────────────────────────────────────────────────

def _to_relative_uri(file_path: str, scan_root: str) -> str:
    """Convert an absolute or mixed file path to a SARIF-relative URI."""
    try:
        rel = os.path.relpath(file_path, scan_root)
    except ValueError:
        # On Windows, relpath can fail across drives
        rel = file_path
    # SARIF URIs use forward slashes
    return rel.replace(os.sep, "/")


# ── Rule lookup helpers ──────────────────────────────────────────────────────

def _lookup_rule(rule_name: str) -> dict:
    """Look up a rule by its human-readable name, with fallback."""
    if rule_name in RULES:
        return RULES[rule_name]
    # Fallback for unknown / future rules
    return {
        "id": "VS000",
        "shortDescription": rule_name,
        "fullDescription": rule_name,
        "defaultLevel": "note",
        "helpUri": "https://github.com/AyushkhatiDev/vibesec",
    }


# ── Public API ───────────────────────────────────────────────────────────────

def generate_sarif(findings: list, scan_root: str = ".") -> dict:
    """
    Convert a list of VibeSec findings into a SARIF 2.1.0 document.

    Parameters
    ----------
    findings : list[dict]
        VibeSec finding dicts with keys: rule, severity, file, line,
        message, fix_hint, code_snippet.
    scan_root : str
        Root directory of the scan, used to compute relative file URIs.

    Returns
    -------
    dict
        A SARIF 2.1.0 document ready to be serialized to JSON.
    """
    scan_root = os.path.abspath(scan_root)

    # Collect unique rules referenced in findings
    seen_rule_names: set = set()
    for f in findings:
        seen_rule_names.add(f["rule"])

    # Build the rules array (only rules that appear in results)
    rules = []
    rule_index_map: dict = {}  # rule_name -> index in rules array
    for rule_name in sorted(seen_rule_names):
        meta = _lookup_rule(rule_name)
        rule_index_map[rule_name] = len(rules)
        rule_entry = {
            "id": meta["id"],
            "name": rule_name,
            "shortDescription": {"text": meta["shortDescription"]},
            "fullDescription": {"text": meta["fullDescription"]},
            "defaultConfiguration": {"level": meta["defaultLevel"]},
            "helpUri": meta["helpUri"],
        }
        rules.append(rule_entry)

    # Build results array
    results = []
    for finding in findings:
        rule_meta = _lookup_rule(finding["rule"])
        level = _severity_to_sarif_level(finding["severity"])

        # Build message text — include fix hint if available
        message_text = finding["message"]
        fix_hint = finding.get("fix_hint")
        if fix_hint:
            message_text = f"{message_text}\nFix: {fix_hint}"

        # Ensure startLine is always a positive integer
        line = finding.get("line")
        if not isinstance(line, int) or line < 1:
            line = 1

        result = {
            "ruleId": rule_meta["id"],
            "ruleIndex": rule_index_map.get(finding["rule"], 0),
            "level": level,
            "message": {"text": message_text},
            "properties": {
                "security-severity": _SEVERITY_SCORES.get(finding["severity"], "5.0"),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _to_relative_uri(finding["file"], scan_root),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line,
                        },
                    }
                }
            ],
        }

        # Include code snippet if available
        snippet = finding.get("code_snippet")
        if snippet:
            result["locations"][0]["physicalLocation"]["region"][
                "snippet"
            ] = {"text": snippet}

        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VibeSec",
                        "version": vibesec.__version__,
                        "semanticVersion": vibesec.__version__,
                        "informationUri": "https://github.com/AyushkhatiDev/vibesec",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": "file:///"},
                },
                "results": results,
            }
        ],
    }

    return sarif


def write_sarif(findings: list, output_path: str, scan_root: str = ".") -> None:
    """
    Generate a SARIF document and write it to *output_path*.

    Parameters
    ----------
    findings : list[dict]
        VibeSec finding dicts.
    output_path : str
        Destination file path for the SARIF JSON.
    scan_root : str
        Root directory of the scan.
    """
    if not output_path:
        output_path = "vibesec-results.sarif"

    sarif = generate_sarif(findings, scan_root)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
