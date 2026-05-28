import re

from vibesec.rules.common import finding, normalized_path

RULE_NAME = "GitHub Actions Security Issue"


def _is_workflow(file_path):
    path = normalized_path(file_path)
    return "/.github/workflows/" in path and path.endswith((".yml", ".yaml"))


def check_github_actions(file_path, content):
    if not _is_workflow(file_path):
        return []

    findings = []
    lines = content.splitlines()
    has_pull_request_target = re.search(r"^\s*pull_request_target\s*:", content, re.M) is not None
    has_checkout = "actions/checkout" in content

    if has_pull_request_target and has_checkout:
        findings.append(finding(
            RULE_NAME, "MEDIUM", file_path, 1,
            "pull_request_target workflow checks out repository code",
            "Avoid checkout under pull_request_target or pin and isolate untrusted code paths.",
            lines[0] if lines else "",
        ))

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.search(r"uses\s*:\s*[^@\s]+@(?:main|master|latest|v?\d+(?:\.\d+)?)\s*$", stripped):
            findings.append(finding(
                RULE_NAME, "MEDIUM", file_path, line_num,
                "GitHub Action is not pinned to a full commit SHA",
                "Pin third-party actions to a full-length commit SHA.", line
            ))
        if re.search(r"echo\s+.*\$\{\{\s*secrets\.", line):
            findings.append(finding(
                RULE_NAME, "MEDIUM", file_path, line_num,
                "Workflow appears to print a secret to logs",
                "Never echo secrets; pass them only to tools that need them.", line
            ))
        if re.search(r"run\s*:\s*.*\$\{\{\s*github\.event\.(issue|pull_request|comment|inputs)", line):
            findings.append(finding(
                RULE_NAME, "HIGH", file_path, line_num,
                "Workflow run command interpolates untrusted github.event data",
                "Pass event data through environment variables and quote/validate before shell use.", line
            ))
        if re.search(r"permissions\s*:\s*write-all", line):
            findings.append(finding(
                RULE_NAME, "MEDIUM", file_path, line_num,
                "Workflow grants write-all permissions",
                "Use least-privilege permissions for each job.", line
            ))
        if re.search(r"runs-on\s*:\s*self-hosted", line):
            findings.append(finding(
                RULE_NAME, "MEDIUM", file_path, line_num,
                "Workflow uses a self-hosted runner",
                "Use self-hosted runners only with trusted workflows and repository isolation.", line
            ))

    return findings
