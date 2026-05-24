import click
from vibesec.scanner import Scanner
from vibesec.reporter import Reporter

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """VibeSec — Security scanner for AI-generated code."""
    pass

@cli.command()
@click.argument("path")
@click.option("--fix", is_flag=True, help="Generate fix suggestions using Groq AI")
@click.option("--output", type=click.Choice(["terminal", "json"]), default="terminal")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
def scan(path, fix, output, severity):
    """Scan a directory or file for security vulnerabilities."""
    
    reporter = Reporter()
    reporter.print_banner()
    
    scanner = Scanner(path)
    findings = scanner.run()
    
    if severity:
        findings = [f for f in findings if f["severity"].lower() == severity]
    
    if output == "json":
        reporter.print_json(findings)
    else:
        reporter.print_report(findings, path, fix)

def main():
    cli()

if __name__ == "__main__":
    main()