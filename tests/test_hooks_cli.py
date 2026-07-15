"""Tests for vibesec hooks CLI — install / status / uninstall."""

import json
import os

import pytest
from click.testing import CliRunner

from vibesec.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def project_dir(tmp_path):
    """Create a temporary project directory."""
    return tmp_path


# ---------------------------------------------------------------------------
# vibesec hooks install
# ---------------------------------------------------------------------------

class TestHooksInstall:
    def test_install_claude_code(self, runner, project_dir):
        result = runner.invoke(
            cli,
            ["hooks", "install", "--client", "claude-code", "--project-dir", str(project_dir)],
        )
        assert result.exit_code == 0
        assert "Claude Code" in result.output

        settings_path = project_dir / ".claude" / "settings.json"
        assert settings_path.exists()

        with open(settings_path) as f:
            settings = json.load(f)
        post_hooks = settings["hooks"]["PostToolUse"]
        assert len(post_hooks) == 1
        assert post_hooks[0]["matcher"] == "Write|Edit|MultiEdit"
        assert "vibesec" in post_hooks[0]["hooks"][0]["command"]

        batch_hooks = settings["hooks"]["PostToolBatch"]
        assert len(batch_hooks) == 1
        assert "vibesec" in batch_hooks[0]["hooks"][0]["command"]
        assert "--batch" in batch_hooks[0]["hooks"][0]["command"]

    def test_install_cursor(self, runner, project_dir):
        result = runner.invoke(
            cli,
            ["hooks", "install", "--client", "cursor", "--project-dir", str(project_dir)],
        )
        assert result.exit_code == 0
        assert "Cursor" in result.output

        hooks_path = project_dir / ".cursor" / "hooks.json"
        assert hooks_path.exists()

        with open(hooks_path) as f:
            hooks_config = json.load(f)
        edit_hooks = hooks_config["hooks"]["afterFileEdit"]
        assert len(edit_hooks) == 1
        assert "vibesec" in edit_hooks[0]["command"]

    def test_install_all(self, runner, project_dir):
        result = runner.invoke(
            cli,
            ["hooks", "install", "--client", "all", "--project-dir", str(project_dir)],
        )
        assert result.exit_code == 0
        assert (project_dir / ".claude" / "settings.json").exists()
        assert (project_dir / ".cursor" / "hooks.json").exists()

    def test_install_idempotent(self, runner, project_dir):
        """Installing twice should not duplicate the hook entry."""
        runner.invoke(
            cli,
            ["hooks", "install", "--client", "claude-code", "--project-dir", str(project_dir)],
        )
        result = runner.invoke(
            cli,
            ["hooks", "install", "--client", "claude-code", "--project-dir", str(project_dir)],
        )
        assert "already installed" in result.output

        with open(project_dir / ".claude" / "settings.json") as f:
            settings = json.load(f)
        assert len(settings["hooks"]["PostToolUse"]) == 1
        assert len(settings["hooks"]["PostToolBatch"]) == 1

    def test_install_autodetect_claude(self, runner, project_dir):
        """Auto-detect when .claude/ directory exists."""
        (project_dir / ".claude").mkdir()
        result = runner.invoke(
            cli,
            ["hooks", "install", "--project-dir", str(project_dir)],
        )
        assert result.exit_code == 0
        assert "Auto-detected" in result.output
        assert "claude-code" in result.output

    def test_install_autodetect_none(self, runner, project_dir):
        """No auto-detected client should show a helpful message."""
        result = runner.invoke(
            cli,
            ["hooks", "install", "--project-dir", str(project_dir)],
        )
        assert "No .claude/ or .cursor/ directory found" in result.output

    def test_install_merges_with_existing_settings(self, runner, project_dir):
        """Should preserve existing settings when adding hooks."""
        claude_dir = project_dir / ".claude"
        claude_dir.mkdir()
        settings_path = claude_dir / "settings.json"
        existing = {"allowedTools": ["Bash"], "customKey": True}
        with open(settings_path, "w") as f:
            json.dump(existing, f)

        runner.invoke(
            cli,
            ["hooks", "install", "--client", "claude-code", "--project-dir", str(project_dir)],
        )

        with open(settings_path) as f:
            settings = json.load(f)
        assert settings["allowedTools"] == ["Bash"]
        assert settings["customKey"] is True
        assert "PostToolUse" in settings["hooks"]
        assert "PostToolBatch" in settings["hooks"]


# ---------------------------------------------------------------------------
# vibesec hooks status
# ---------------------------------------------------------------------------

class TestHooksStatus:
    def test_status_nothing_installed(self, runner, project_dir):
        result = runner.invoke(
            cli,
            ["hooks", "status", "--project-dir", str(project_dir)],
        )
        assert result.exit_code == 0
        assert "not configured" in result.output

    def test_status_after_install(self, runner, project_dir):
        runner.invoke(
            cli,
            ["hooks", "install", "--client", "all", "--project-dir", str(project_dir)],
        )
        result = runner.invoke(
            cli,
            ["hooks", "status", "--project-dir", str(project_dir)],
        )
        assert "active" in result.output
        assert "block_on" in result.output


# ---------------------------------------------------------------------------
# vibesec hooks uninstall
# ---------------------------------------------------------------------------

class TestHooksUninstall:
    def test_uninstall_claude_code(self, runner, project_dir):
        runner.invoke(
            cli,
            ["hooks", "install", "--client", "claude-code", "--project-dir", str(project_dir)],
        )
        result = runner.invoke(
            cli,
            ["hooks", "uninstall", "--client", "claude-code", "--project-dir", str(project_dir)],
        )
        assert result.exit_code == 0
        assert "Removed Claude Code hooks" in result.output

        with open(project_dir / ".claude" / "settings.json") as f:
            settings = json.load(f)
        assert "hooks" not in settings  # cleaned up empty structure

    def test_uninstall_cursor(self, runner, project_dir):
        runner.invoke(
            cli,
            ["hooks", "install", "--client", "cursor", "--project-dir", str(project_dir)],
        )
        result = runner.invoke(
            cli,
            ["hooks", "uninstall", "--client", "cursor", "--project-dir", str(project_dir)],
        )
        assert result.exit_code == 0
        assert "Removed Cursor hook" in result.output

    def test_uninstall_when_not_installed(self, runner, project_dir):
        result = runner.invoke(
            cli,
            ["hooks", "uninstall", "--project-dir", str(project_dir)],
        )
        assert "No hooks were removed" in result.output

    def test_uninstall_preserves_other_hooks(self, runner, project_dir):
        """Uninstall should only remove VibeSec hooks, not other hooks."""
        claude_dir = project_dir / ".claude"
        claude_dir.mkdir()
        settings = {
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "echo other"}],
                    },
                    {
                        "matcher": "Write|Edit|MultiEdit",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python3 -m vibesec.hook_runner",
                            }
                        ],
                    },
                ]
            }
        }
        with open(claude_dir / "settings.json", "w") as f:
            json.dump(settings, f)

        result = runner.invoke(
            cli,
            ["hooks", "uninstall", "--client", "claude-code", "--project-dir", str(project_dir)],
        )
        assert "Removed" in result.output

        with open(claude_dir / "settings.json") as f:
            updated = json.load(f)
        # The "echo other" hook should survive
        assert len(updated["hooks"]["PostToolUse"]) == 1
        assert "other" in updated["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
