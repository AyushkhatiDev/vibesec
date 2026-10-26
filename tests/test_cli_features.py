from click.testing import CliRunner

from vibesec import __version__
from vibesec.cli import cli


def test_ignore_flag_filters_findings(tmp_path):
    target = tmp_path / "migration.sql"
    target.write_text("ALTER TABLE users DISABLE ROW LEVEL SECURITY;", encoding="utf-8")
    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--ignore", "rls"])
    assert result.exit_code == 0
    assert "No vulnerabilities found" in result.output


def test_version_flag_works():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_nonexistent_path_shows_error():
    result = CliRunner().invoke(cli, ["scan", "/definitely/not/a/real/path"])
    assert result.exit_code == 0
    assert "does not exist" in result.output


def test_fail_on_exits_with_error_when_vulnerabilities_found(tmp_path):
    target = tmp_path / "app.py"
    target.write_text('api_key = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"', encoding="utf-8")
    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 1


def test_fail_on_passes_when_severity_is_below_threshold(tmp_path):
    target = tmp_path / "cors.js"
    target.write_text('app.use(cors({ origin: "*" }))', encoding="utf-8")
    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0
