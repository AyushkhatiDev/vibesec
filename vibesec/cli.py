import sys

import click

from vibesec import __version__
from vibesec.scanner import Scanner
from vibesec.reporter import Reporter

@click.group()
@click.version_option(version=__version__)
def cli():
    """VibeSec — Security scanner for AI-generated code."""
    pass

@cli.command()
@click.argument("path")
@click.option("--fix", is_flag=True, help="Generate fix suggestions using Groq AI")
@click.option(
    "--output",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    help="Output format (default: terminal)",
)
@click.option(
    "--sarif-output",
    default="vibesec-results.sarif",
    help="Output file path for SARIF format (default: vibesec-results.sarif)",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Filter findings by minimum severity",
)
def scan(path, fix, output, sarif_output, severity):
    """Scan a directory or file for security vulnerabilities."""

    reporter = Reporter()

    # Only print banner for terminal output
    if output == "terminal":
        reporter.print_banner()

    scanner = Scanner(path)
    findings = scanner.run()

    if severity:
        findings = [f for f in findings if f["severity"].lower() == severity]

    if output == "json":
        reporter.print_json(findings)
    elif output == "sarif":
        from vibesec.sarif_reporter import write_sarif
        write_sarif(findings, sarif_output, scan_root=path)
        click.echo(
            f"SARIF report written to {sarif_output} "
            f"({len(findings)} finding{'s' if len(findings) != 1 else ''})",
            err=True,
        )
    else:
        reporter.print_report(findings, path, fix)

    # Exit with code 1 when findings exist in CI-oriented modes
    if output in ("json", "sarif") and findings:
        sys.exit(1)

def main():
    cli()

if __name__ == "__main__":
    main()