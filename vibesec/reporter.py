import json
from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from vibesec import __version__

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "bold orange3",
    "LOW": "bold green",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class Reporter:

    def print_banner(self):
        console.print()
        console.print(Panel(
            f"[bold cyan]VibeSec v{__version__}[/bold cyan] — [dim]AI-Generated Code Security Scanner[/dim]",
            border_style="cyan",
            expand=False
        ))
        console.print()

    def print_report(self, findings, path, fix=False, files_scanned=None, duration=None):
        from vibesec.rules import ALL_RULES

        if not findings:
            details = f"VibeSec checked {len(ALL_RULES)} vulnerability patterns."
            if files_scanned is not None:
                details += f"\nFiles scanned: {files_scanned}"
            if duration is not None:
                details += f"\nScan duration: {duration:.2f}s"
            console.print(Panel(
                "[bold green]✓ No vulnerabilities found![/bold green]\n"
                f"[dim]{details}[/dim]",
                border_style="green"
            ))
            return

        # Sort by severity
        findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

        # Summary
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        risk_score = (
            counts.get("CRITICAL", 0) * 10
            + counts.get("HIGH", 0) * 5
            + counts.get("MEDIUM", 0) * 2
            + counts.get("LOW", 0)
        )
        risk_color = "green" if risk_score < 10 else "yellow" if risk_score <= 30 else "red"

        by_file = defaultdict(list)
        for finding in findings:
            by_file[finding["file"]].append(finding)
        most_vulnerable_file, most_vulnerable_findings = max(
            by_file.items(),
            key=lambda item: len(item[1]),
        )

        summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        summary.add_column(style="bold")
        summary.add_column()

        for severity, count in counts.items():
            if count > 0:
                color = SEVERITY_COLORS[severity]
                summary.add_row(
                    f"[{color}]● {severity}[/{color}]",
                    f"[{color}]{count} finding{'s' if count > 1 else ''}[/{color}]"
                )

        summary.add_row(f"[{risk_color}]Risk score[/{risk_color}]", f"[{risk_color}]{risk_score}[/{risk_color}]")
        if files_scanned is not None:
            summary.add_row("Files scanned", str(files_scanned))
        if duration is not None:
            summary.add_row("Scan duration", f"{duration:.2f}s")
        summary.add_row("Rules checked", str(len(ALL_RULES)))
        summary.add_row("Most vulnerable file", f"{most_vulnerable_file} ({len(most_vulnerable_findings)})")

        console.print(Panel(summary, title="[bold]FINDINGS SUMMARY[/bold]",
                           border_style="dim"))

        # Generate AI fixes if requested
        if fix:
            from vibesec.fixgen import generate_fix
            console.print("\n  [cyan]Generating AI fix suggestions...[/cyan]\n")
            for finding in findings:
                finding["groq_fix"] = generate_fix(finding)

        # Findings grouped by file
        for file_path in sorted(by_file):
            console.print()
            console.print(f"  [bold white]{file_path}[/bold white]")
            for finding in by_file[file_path]:
                severity = finding["severity"]
                color = SEVERITY_COLORS[severity]
                console.print(f"    [{color}]{severity}[/{color}] — [bold]{finding['rule']}[/bold] line {finding.get('line', 'N/A')}")
                console.print(f"    [red]Found:[/red] {finding['message']}")
                console.print(f"    [green]Fix:[/green]   {finding['fix_hint']}")

                if fix and finding.get("groq_fix"):
                    console.print(f"    [cyan]AI Fix:[/cyan] {finding['groq_fix']}")

        # Footer
        console.print()
        console.print(
            f"  [dim]{len(findings)} finding{'s' if len(findings) > 1 else ''} "
            f"in {path}[/dim]"
        )
        if not fix:
            console.print(
                "  [dim]Run with [/dim][cyan]--fix[/cyan]"
                "[dim] for AI-powered remediation suggestions[/dim]"
            )
        console.print()

    def print_json(self, findings):
        console.print(json.dumps(findings, indent=2))

    def print_sarif(self, findings, output_path, scan_root="."):
        from vibesec.sarif_reporter import write_sarif

        write_sarif(findings, output_path, scan_root=scan_root)
        console.print(f"  [green]SARIF written to {output_path}[/green]")
