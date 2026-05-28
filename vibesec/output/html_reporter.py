import html
from collections import Counter, defaultdict


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _risk_score(findings):
    counts = Counter(f["severity"] for f in findings)
    return counts["CRITICAL"] * 10 + counts["HIGH"] * 5 + counts["MEDIUM"] * 2 + counts["LOW"]


def generate_html_report(findings, output_path, scan_path="", files_scanned=None, duration=None):
    """Write a self-contained HTML report."""
    by_file = defaultdict(list)
    for finding in sorted(findings, key=lambda f: (f["file"], SEVERITY_ORDER.get(f["severity"], 99))):
        by_file[finding["file"]].append(finding)

    counts = Counter(f["severity"] for f in findings)
    risk = _risk_score(findings)
    risk_class = "low" if risk < 10 else "medium" if risk <= 30 else "high"

    rows = "".join(
        f"<tr><th>{sev}</th><td>{counts.get(sev, 0)}</td></tr>"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )

    file_sections = []
    for file_path, file_findings in by_file.items():
        items = []
        for f in file_findings:
            snippet = html.escape(str(f.get("code_snippet", "")))
            items.append(
                "<article class='finding'>"
                f"<div><span class='badge {f['severity'].lower()}'>{f['severity']}</span> "
                f"<strong>{html.escape(f['rule'])}</strong> line {html.escape(str(f.get('line', 'N/A')))}</div>"
                f"<p>{html.escape(f['message'])}</p>"
                f"<p class='fix'>{html.escape(f.get('fix_hint', ''))}</p>"
                f"<pre><code>{snippet}</code></pre>"
                "</article>"
            )
        file_sections.append(
            f"<section><h2>{html.escape(file_path)}</h2>{''.join(items)}</section>"
        )

    body = "".join(file_sections) or "<p class='clean'>No findings.</p>"

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VibeSec Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #1f2937; }}
    header {{ border-bottom: 1px solid #d1d5db; margin-bottom: 24px; padding-bottom: 16px; }}
    h1 {{ margin: 0 0 8px; }}
    table {{ border-collapse: collapse; margin: 16px 0; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px 12px; text-align: left; }}
    section {{ margin: 24px 0; }}
    .finding {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 14px; margin: 12px 0; }}
    .badge {{ border-radius: 999px; color: white; display: inline-block; font-size: 12px; padding: 3px 8px; }}
    .critical {{ background: #b91c1c; }} .high {{ background: #c2410c; }}
    .medium {{ background: #a16207; }} .low {{ background: #15803d; }}
    .risk.low {{ color: #15803d; }} .risk.medium {{ color: #a16207; }} .risk.high {{ color: #b91c1c; }}
    pre {{ background: #111827; color: #f9fafb; overflow-x: auto; padding: 12px; border-radius: 6px; }}
    .fix {{ color: #047857; }}
  </style>
</head>
<body>
  <header>
    <h1>VibeSec Security Report</h1>
    <div>Target: {html.escape(scan_path)}</div>
    <div>Files scanned: {html.escape(str(files_scanned if files_scanned is not None else "N/A"))}</div>
    <div>Duration: {html.escape(f"{duration:.2f}s" if duration is not None else "N/A")}</div>
    <div class="risk {risk_class}">Risk score: {risk}</div>
  </header>
  <table>{rows}</table>
  {body}
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(document)
