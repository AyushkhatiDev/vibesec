from vibesec.output.html_reporter import generate_html_report


def test_html_output(tmp_path):
    output = tmp_path / "report.html"
    findings = [{
        "rule": "Test Rule",
        "severity": "HIGH",
        "file": "app.py",
        "line": 1,
        "message": "bad thing",
        "fix_hint": "fix it",
        "code_snippet": "bad()",
    }]
    generate_html_report(findings, str(output), scan_path=".", files_scanned=1, duration=0.1)
    html = output.read_text(encoding="utf-8")
    assert "VibeSec Security Report" in html
    assert "Test Rule" in html
    assert "Risk score" in html
