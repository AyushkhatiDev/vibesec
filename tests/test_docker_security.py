from vibesec.rules.docker_security import check_docker_security


def test_detects_root_dockerfile():
    assert check_docker_security("Dockerfile", "FROM python:3.11\nCMD python app.py")


def test_detects_secret_env():
    assert check_docker_security("Dockerfile", "FROM python:3.11\nENV SECRET_KEY=abc123\nUSER app\nCMD run")


def test_detects_compose_privileged():
    assert check_docker_security("docker-compose.yml", "services:\n  app:\n    privileged: true\n    restart: unless-stopped")


def test_allows_user_directive():
    findings = check_docker_security("Dockerfile", "FROM python:3.11\nUSER app\nCMD python app.py")
    assert not any("root" in f["message"] for f in findings)


def test_allows_restart_policy():
    findings = check_docker_security("docker-compose.yml", "services:\n  app:\n    restart: unless-stopped")
    assert not any("restart" in f["message"] for f in findings)


def test_detects_exposed_database_edge_case():
    assert check_docker_security("docker-compose.yml", 'ports:\n  - "0.0.0.0:5432:5432"\nrestart: always')
