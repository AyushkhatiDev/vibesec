import os
import click
from rich.console import Console

from vibesec import __version__
from vibesec.reporter import Reporter
from vibesec.scanner import Scanner
from vibesec.utils import is_github_url

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="vibesec")
def cli():
    """VibeSec command-line interface."""


@cli.command()
@click.argument("path")
@click.option("--fix", is_flag=True, help="Generate fix suggestions using Groq AI")
@click.option("--output", type=click.Choice(["terminal", "json", "sarif"]), default="terminal")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
@click.option("--sarif-output", default="vibesec-results.sarif", help="SARIF output file path")
@click.option("--ignore", default="", help="Comma-separated rules to ignore e.g. rls,cors")
def scan(path, fix, output, severity, sarif_output, ignore):
    """Scan a directory, file, or GitHub repository URL."""

    reporter = Reporter()
    reporter.print_banner()

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
        scanner = Scanner(scan_path, display_path=path)
        findings = scanner.run()

        if ignore:
            ignore_list = [r.strip().lower() for r in ignore.split(",") if r.strip()]
            findings = [
                f for f in findings
                if not any(ig in f["rule"].lower() for ig in ignore_list)
            ]

        if severity:
            findings = [f for f in findings if f["severity"].lower() == severity]

        if output == "json":
            reporter.print_json(findings)
        elif output == "sarif":
            reporter.print_sarif(findings, sarif_output)
        else:
            reporter.print_report(findings, path, fix)
    finally:
        # Clean up temp directory
        if tmp_dir:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


def main():
    cli()


if __name__ == "__main__":
    main()
