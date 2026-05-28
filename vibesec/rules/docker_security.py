import re

from vibesec.rules.common import finding, filename, has_dockerignore, normalized_path

RULE_NAME = "Docker Security Issue"


def _is_dockerfile(file_path):
    name = filename(file_path).lower()
    return name == "dockerfile" or name.startswith("dockerfile.")


def _is_compose(file_path):
    name = filename(file_path).lower()
    return name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def _skip(file_path):
    path = normalized_path(file_path).lower()
    return "/tests/" in path or "/test/" in path or "test-app/" in path


def _check_dockerfile(file_path, content):
    findings = []
    lines = content.splitlines()
    user_seen = False
    cmd_line = None
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        upper = stripped.upper()
        if not stripped or stripped.startswith("#"):
            continue
        if upper.startswith("USER "):
            user_seen = True
        if upper.startswith(("CMD ", "ENTRYPOINT ")) and cmd_line is None:
            cmd_line = (line_num, line)
        if re.search(r"^FROM\s+\S+:latest\b", stripped, re.I):
            findings.append(finding(RULE_NAME, "MEDIUM", file_path, line_num, "Docker base image uses latest tag", "Pin base images to immutable versions or digests.", line))
        if re.search(r"^(ENV|ARG)\s+\w*(SECRET|KEY|PASSWORD|TOKEN)\w*\s*=\s*\S+", stripped, re.I):
            findings.append(finding(RULE_NAME, "HIGH", file_path, line_num, "Dockerfile contains secret-like ENV/ARG default", "Pass secrets at runtime through a secret manager, not Dockerfile ENV/ARG defaults.", line))
        if re.search(r"^RUN\s+.*curl\b.*\|\s*(ba)?sh\b", stripped, re.I):
            findings.append(finding(RULE_NAME, "MEDIUM", file_path, line_num, "Dockerfile pipes curl output to shell", "Download, verify checksums/signatures, then execute trusted installers.", line))
        if re.search(r"^COPY\s+\.\s+\.", stripped, re.I) and not has_dockerignore(file_path):
            findings.append(finding(RULE_NAME, "MEDIUM", file_path, line_num, "COPY . . used without nearby .dockerignore", "Add .dockerignore to keep secrets, tests, and build artifacts out of images.", line))

    if cmd_line and not user_seen:
        line_num, line = cmd_line
        findings.append(finding(RULE_NAME, "HIGH", file_path, line_num, "Dockerfile runs as root because no USER directive appears before CMD/ENTRYPOINT", "Create and switch to a non-root user before running the app.", line))
    return findings


def _check_compose(file_path, content):
    findings = []
    lines = content.splitlines()
    has_restart = any(re.match(r"\s*restart\s*:", line) for line in lines)
    for line_num, line in enumerate(lines, 1):
        if re.search(r"\bprivileged\s*:\s*true\b", line, re.I):
            findings.append(finding(RULE_NAME, "HIGH", file_path, line_num, "docker-compose enables privileged mode", "Remove privileged mode unless absolutely required.", line))
        if re.search(r"0\.0\.0\.0:5432:5432", line):
            findings.append(finding(RULE_NAME, "MEDIUM", file_path, line_num, "Database port is exposed on all interfaces", "Bind database ports to localhost or private networks only.", line))
        if re.search(r"(POSTGRES_PASSWORD|MYSQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*[:=]\s*['\"]?(password|changeme|secret|admin)", line, re.I):
            findings.append(finding(RULE_NAME, "HIGH", file_path, line_num, "docker-compose contains hardcoded database password", "Use Docker secrets or environment injection outside source control.", line))
    if content.strip() and not has_restart:
        findings.append(finding(RULE_NAME, "MEDIUM", file_path, 1, "docker-compose service lacks restart policy", "Set an appropriate restart policy for production services.", lines[0] if lines else ""))
    return findings


def check_docker_security(file_path, content):
    if _skip(file_path):
        return []
    if _is_dockerfile(file_path):
        return _check_dockerfile(file_path, content)
    if _is_compose(file_path):
        return _check_compose(file_path, content)
    return []
