import json
import os
import shutil
import click
from rich.console import Console

from vibesec import __version__
from vibesec.config import load_config, merge_ignore

console = Console(stderr=True)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Path to the bundled hooks directory (relative to this file)
_HOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hooks")


@click.group()
@click.version_option(version=__version__, prog_name="vibesec")
def cli():
    """VibeSec command-line interface."""


@cli.command()
@click.argument("path")
@click.option("--fix", is_flag=True, help="Generate fix suggestions using Groq AI")
@click.option("--output", type=click.Choice(["terminal", "json", "sarif", "html"]), default="terminal")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
@click.option("--sarif-output", default="vibesec-results.sarif", help="SARIF output file path")
@click.option("--html-output", default="report.html", help="HTML output file path")
@click.option("--ignore", default="", help="Comma-separated rules to ignore e.g. rls,cors")
def scan(path, fix, output, severity, sarif_output, html_output, ignore):
    """Scan a directory, file, or GitHub repository URL."""
    from vibesec.reporter import Reporter
    from vibesec.scanner import Scanner
    from vibesec.utils import is_github_url

    reporter = Reporter()
    reporter.print_banner()

    config = load_config(path)

    # Handle GitHub URLs
    tmp_dir = None
    if is_github_url(path):
        from vibesec.utils import clone_github_repo
        console.print("  [cyan]Cloning repository...[/cyan]")
        try:
            tmp_dir = clone_github_repo(path)
            scan_path = tmp_dir
            console.print("  [green]Cloned successfully[/green]\n")
        except Exception as exc:
            console.print(f"  [red]Error: {exc}[/red]")
            return
    else:
        scan_path = path

    if not os.path.exists(scan_path):
        console.print(f"[red]Error: Path '{scan_path}' does not exist.[/red]")
        return

    try:
        scanner = Scanner(
            scan_path,
            display_path=path,
            exclude_paths=config.get("exclude_paths") or [],
            max_file_size=config.get("max_file_size"),
        )
        findings = scanner.run()

        ignore_list = merge_ignore(config, ignore)
        if ignore_list:
            findings = [
                f for f in findings
                if not any(ig in f["rule"].lower() for ig in ignore_list)
            ]

        if severity:
            findings = [f for f in findings if f["severity"].lower() == severity]
        elif config.get("severity_threshold"):
            threshold = SEVERITY_ORDER.get(str(config["severity_threshold"]).lower())
            if threshold is not None:
                findings = [
                    f for f in findings
                    if SEVERITY_ORDER.get(f["severity"].lower(), 99) <= threshold
                ]

        if output == "json":
            reporter.print_json(findings)
        elif output == "sarif":
            reporter.print_sarif(findings, sarif_output)
        elif output == "html":
            from vibesec.output.html_reporter import generate_html_report
            generate_html_report(
                findings,
                html_output,
                scan_path=path,
                files_scanned=scanner.files_scanned,
                duration=scanner.duration,
            )
            console.print(f"  [green]HTML report written to {html_output}[/green]")
        else:
            reporter.print_report(
                findings,
                path,
                fix,
                files_scanned=scanner.files_scanned,
                duration=scanner.duration,
            )
    finally:
        # Clean up temp directory
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# vibesec hooks — install / status / uninstall
# ---------------------------------------------------------------------------

@cli.group()
def hooks():
    """Manage VibeSec enforcement hooks for AI coding agents."""


def _detect_client(project_dir):
    """Auto-detect the AI coding client by checking for config directories."""
    detected = []
    if os.path.isdir(os.path.join(project_dir, ".claude")):
        detected.append("claude-code")
    if os.path.isdir(os.path.join(project_dir, ".cursor")):
        detected.append("cursor")
    return detected


def _install_claude_code(project_dir):
    """Install VibeSec PostToolUse and PostToolBatch hooks for Claude Code."""
    claude_dir = os.path.join(project_dir, ".claude")
    os.makedirs(claude_dir, exist_ok=True)

    settings_path = os.path.join(claude_dir, "settings.json")

    # The hook configs we want to install
    vibesec_hook_entry = {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
            {
                "type": "command",
                "command": "python3 -m vibesec.hook_runner",
                "timeout": 30,
            }
        ],
    }
    vibesec_batch_entry = {
        "hooks": [
            {
                "type": "command",
                "command": "python3 -m vibesec.hook_runner --batch",
                "timeout": 30,
            }
        ],
    }

    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
        except (json.JSONDecodeError, OSError):
            settings = {}
    else:
        settings = {}

    # Merge into existing hooks
    if "hooks" not in settings:
        settings["hooks"] = {}
    if "PostToolUse" not in settings["hooks"]:
        settings["hooks"]["PostToolUse"] = []
    if "PostToolBatch" not in settings["hooks"]:
        settings["hooks"]["PostToolBatch"] = []

    # Check if we already have a vibesec hook in PostToolUse
    existing_use = settings["hooks"]["PostToolUse"]
    already_installed_use = any(
        "vibesec" in str(h.get("hooks", [{}])[0].get("command", ""))
        for h in existing_use
        if isinstance(h, dict)
    )

    # Check if we already have a vibesec hook in PostToolBatch
    existing_batch = settings["hooks"]["PostToolBatch"]
    already_installed_batch = any(
        "vibesec" in str(h.get("hooks", [{}])[0].get("command", ""))
        for h in existing_batch
        if isinstance(h, dict)
    )

    if already_installed_use and already_installed_batch:
        console.print("  [yellow]Claude Code hooks already installed[/yellow]")
        return False

    if not already_installed_use:
        existing_use.append(vibesec_hook_entry)
    if not already_installed_batch:
        existing_batch.append(vibesec_batch_entry)

    with open(settings_path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")

    # Also copy the shell wrapper for users who prefer it
    hook_script_src = os.path.join(_HOOKS_DIR, "claude_code.sh")
    if os.path.exists(hook_script_src):
        hook_script_dst = os.path.join(claude_dir, "vibesec_hook.sh")
        shutil.copy2(hook_script_src, hook_script_dst)
        os.chmod(hook_script_dst, 0o755)

    console.print("  [green]✓[/green] Claude Code PostToolUse and PostToolBatch hooks installed")
    console.print(f"    Settings: [cyan]{settings_path}[/cyan]")
    return True


def _install_cursor(project_dir):
    """Install VibeSec afterFileEdit hook for Cursor."""
    cursor_dir = os.path.join(project_dir, ".cursor")
    os.makedirs(cursor_dir, exist_ok=True)

    hooks_path = os.path.join(cursor_dir, "hooks.json")

    vibesec_hook_entry = {
        "command": "python3 -m vibesec.hook_runner",
    }

    if os.path.exists(hooks_path):
        try:
            with open(hooks_path, "r", encoding="utf-8") as f:
                hooks_config = json.load(f)
        except (json.JSONDecodeError, OSError):
            hooks_config = {}
    else:
        hooks_config = {}

    if "version" not in hooks_config:
        hooks_config["version"] = 1
    if "hooks" not in hooks_config:
        hooks_config["hooks"] = {}
    if "afterFileEdit" not in hooks_config["hooks"]:
        hooks_config["hooks"]["afterFileEdit"] = []

    existing = hooks_config["hooks"]["afterFileEdit"]
    already_installed = any(
        "vibesec" in str(h.get("command", ""))
        for h in existing
        if isinstance(h, dict)
    )
    if already_installed:
        console.print("  [yellow]Cursor hook already installed[/yellow]")
        return False

    existing.append(vibesec_hook_entry)

    with open(hooks_path, "w", encoding="utf-8") as f:
        json.dump(hooks_config, f, indent=2)
        f.write("\n")

    console.print("  [green]✓[/green] Cursor afterFileEdit hook installed")
    console.print(f"    Config: [cyan]{hooks_path}[/cyan]")
    return True


@hooks.command()
@click.option(
    "--client",
    type=click.Choice(["claude-code", "cursor", "all"]),
    default=None,
    help="Target client. Auto-detects if not specified.",
)
@click.option(
    "--project-dir",
    default=".",
    help="Project root directory (default: current directory).",
)
def install(client, project_dir):
    """Install VibeSec enforcement hooks for AI coding agents."""
    project_dir = os.path.abspath(project_dir)
    console.print(f"\n  [bold]VibeSec Hook Installer[/bold]")
    console.print(f"  Project: {project_dir}\n")

    targets = []
    if client == "all":
        targets = ["claude-code", "cursor"]
    elif client:
        targets = [client]
    else:
        # Auto-detect
        detected = _detect_client(project_dir)
        if detected:
            targets = detected
            console.print(f"  Auto-detected: [cyan]{', '.join(detected)}[/cyan]\n")
        else:
            console.print(
                "  [yellow]No .claude/ or .cursor/ directory found.[/yellow]\n"
                "  Use --client to specify, or create the directory first.\n"
                "  Example: vibesec hooks install --client claude-code\n"
            )
            return

    installed = 0
    for target in targets:
        if target == "claude-code":
            if _install_claude_code(project_dir):
                installed += 1
        elif target == "cursor":
            if _install_cursor(project_dir):
                installed += 1

    if installed:
        console.print(f"\n  [green]{installed} hook(s) installed.[/green]")
        console.print(
            "  Hooks block on CRITICAL and HIGH findings by default.\n"
            "  Configure via [vibesec.hooks] in vibesec.toml.\n"
        )


@hooks.command()
@click.option(
    "--project-dir",
    default=".",
    help="Project root directory (default: current directory).",
)
def status(project_dir):
    """Show which VibeSec enforcement hooks are installed."""
    project_dir = os.path.abspath(project_dir)
    console.print(f"\n  [bold]VibeSec Hook Status[/bold]")
    console.print(f"  Project: {project_dir}\n")

    # Claude Code
    claude_settings = os.path.join(project_dir, ".claude", "settings.json")
    if os.path.exists(claude_settings):
        try:
            with open(claude_settings, "r", encoding="utf-8") as f:
                settings = json.load(f)
            
            post_hooks = settings.get("hooks", {}).get("PostToolUse", [])
            has_use = any(
                "vibesec" in str(h.get("hooks", [{}])[0].get("command", ""))
                for h in post_hooks
                if isinstance(h, dict)
            )
            
            batch_hooks = settings.get("hooks", {}).get("PostToolBatch", [])
            has_batch = any(
                "vibesec" in str(h.get("hooks", [{}])[0].get("command", ""))
                for h in batch_hooks
                if isinstance(h, dict)
            )
            
            if has_use and has_batch:
                console.print("  [green]✓[/green] Claude Code — PostToolUse and PostToolBatch hooks active")
            elif has_use:
                console.print("  [green]✓[/green] Claude Code — PostToolUse hook active (PostToolBatch missing)")
            elif has_batch:
                console.print("  [green]✓[/green] Claude Code — PostToolBatch hook active (PostToolUse missing)")
            else:
                console.print("  [dim]✗[/dim] Claude Code — settings.json exists but no VibeSec hooks configured")
        except Exception:
            console.print("  [dim]✗[/dim] Claude Code — settings.json unreadable")
    else:
        console.print("  [dim]✗[/dim] Claude Code — not configured")

    # Cursor
    cursor_hooks = os.path.join(project_dir, ".cursor", "hooks.json")
    if os.path.exists(cursor_hooks):
        try:
            with open(cursor_hooks, "r", encoding="utf-8") as f:
                hooks_config = json.load(f)
            edit_hooks = hooks_config.get("hooks", {}).get("afterFileEdit", [])
            has_vibesec = any(
                "vibesec" in str(h.get("command", ""))
                for h in edit_hooks
                if isinstance(h, dict)
            )
            if has_vibesec:
                console.print("  [green]✓[/green] Cursor — afterFileEdit hook active")
            else:
                console.print("  [dim]✗[/dim] Cursor — hooks.json exists but no VibeSec hook")
        except Exception:
            console.print("  [dim]✗[/dim] Cursor — hooks.json unreadable")
    else:
        console.print("  [dim]✗[/dim] Cursor — not configured")

    # Config
    from vibesec.config import load_hooks_config
    hooks_cfg = load_hooks_config(project_dir)
    console.print(f"\n  Hook config:")
    console.print(f"    block_on: {hooks_cfg['block_on']}")
    console.print(f"    timeout:  {hooks_cfg['timeout']}s")
    console.print(f"    enabled:  {hooks_cfg['enabled']}")
    console.print()


@hooks.command()
@click.option(
    "--client",
    type=click.Choice(["claude-code", "cursor", "all"]),
    default="all",
    help="Target client to remove hooks from.",
)
@click.option(
    "--project-dir",
    default=".",
    help="Project root directory (default: current directory).",
)
def uninstall(client, project_dir):
    """Remove VibeSec enforcement hooks."""
    project_dir = os.path.abspath(project_dir)
    console.print(f"\n  [bold]VibeSec Hook Uninstaller[/bold]\n")

    targets = ["claude-code", "cursor"] if client == "all" else [client]
    removed = 0

    for target in targets:
        if target == "claude-code":
            settings_path = os.path.join(project_dir, ".claude", "settings.json")
            if os.path.exists(settings_path):
                try:
                    with open(settings_path, "r", encoding="utf-8") as f:
                        settings = json.load(f)
                    
                    hooks_section = settings.get("hooks", {})
                    modified = False
                    
                    # 1. PostToolUse
                    post_hooks = hooks_section.get("PostToolUse", [])
                    original_use_count = len(post_hooks)
                    filtered_use = [
                        h for h in post_hooks
                        if not (
                            isinstance(h, dict)
                            and "vibesec" in str(h.get("hooks", [{}])[0].get("command", ""))
                        )
                    ]
                    if len(filtered_use) < original_use_count:
                        hooks_section["PostToolUse"] = filtered_use
                        if not hooks_section["PostToolUse"]:
                            del hooks_section["PostToolUse"]
                        modified = True
                    
                    # 2. PostToolBatch
                    batch_hooks = hooks_section.get("PostToolBatch", [])
                    original_batch_count = len(batch_hooks)
                    filtered_batch = [
                        h for h in batch_hooks
                        if not (
                            isinstance(h, dict)
                            and "vibesec" in str(h.get("hooks", [{}])[0].get("command", ""))
                        )
                    ]
                    if len(filtered_batch) < original_batch_count:
                        hooks_section["PostToolBatch"] = filtered_batch
                        if not hooks_section["PostToolBatch"]:
                            del hooks_section["PostToolBatch"]
                        modified = True
                    
                    if modified:
                        if not hooks_section:
                            if "hooks" in settings:
                                del settings["hooks"]
                        else:
                            settings["hooks"] = hooks_section
                            
                        with open(settings_path, "w", encoding="utf-8") as f:
                            json.dump(settings, f, indent=2)
                            f.write("\n")
                        console.print("  [green]✓[/green] Removed Claude Code hooks")
                        removed += 1

                        # Remove shell wrapper if present
                        wrapper = os.path.join(project_dir, ".claude", "vibesec_hook.sh")
                        if os.path.exists(wrapper):
                            os.remove(wrapper)
                    else:
                        console.print("  [dim]✗[/dim] Claude Code — no VibeSec hooks found")
                except Exception as e:
                    console.print(f"  [red]Error reading Claude Code settings: {e}[/red]")

        elif target == "cursor":
            hooks_path = os.path.join(project_dir, ".cursor", "hooks.json")
            if os.path.exists(hooks_path):
                try:
                    with open(hooks_path, "r", encoding="utf-8") as f:
                        hooks_config = json.load(f)
                    edit_hooks = hooks_config.get("hooks", {}).get("afterFileEdit", [])
                    original_count = len(edit_hooks)
                    filtered = [
                        h for h in edit_hooks
                        if not (
                            isinstance(h, dict)
                            and "vibesec" in str(h.get("command", ""))
                        )
                    ]
                    if len(filtered) < original_count:
                        hooks_config["hooks"]["afterFileEdit"] = filtered
                        if not hooks_config["hooks"]["afterFileEdit"]:
                            del hooks_config["hooks"]["afterFileEdit"]
                        if not hooks_config["hooks"]:
                            del hooks_config["hooks"]
                        with open(hooks_path, "w", encoding="utf-8") as f:
                            json.dump(hooks_config, f, indent=2)
                            f.write("\n")
                        console.print("  [green]✓[/green] Removed Cursor hook")
                        removed += 1
                    else:
                        console.print("  [dim]✗[/dim] Cursor — no VibeSec hook found")
                except Exception as e:
                    console.print(f"  [red]Error reading Cursor hooks: {e}[/red]")

    if removed:
        console.print(f"\n  [green]{removed} hook(s) removed.[/green]\n")
    else:
        console.print("\n  No hooks were removed.\n")


def main():
    cli()


if __name__ == "__main__":
    main()

