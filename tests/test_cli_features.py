from click.testing import CliRunner

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
    assert "0.7.0" in result.output


def test_nonexistent_path_shows_error():
    result = CliRunner().invoke(cli, ["scan", "/definitely/not/a/real/path"])
    assert result.exit_code == 0
    assert "does not exist" in result.output
