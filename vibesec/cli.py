import os
import click
from rich.console import Console

from vibesec import __version__
from vibesec.config import load_config, merge_ignore
from vibesec.reporter import Reporter
from vibesec.scanner import Scanner
from vibesec.utils import is_github_url

console = Console()
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


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
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


def main():
    cli()


if __name__ == "__main__":
    main()
