import json
import re
import shutil
import subprocess
import tempfile


TAINT_SOURCES = ("req.query", "req.body", "req.params")
SINKS = ("res.send", "db.query", "exec", "child_process.exec")


def parse_js_ast(content):
    """Parse JS/TS with Node and @babel/parser/acorn when available."""
    if not shutil.which("node"):
        return None

    script = """
const fs = require('fs');
const source = fs.readFileSync(process.argv[1], 'utf8');
let parser;
try { parser = require('@babel/parser'); }
catch (e) {
  try { parser = require('acorn'); }
  catch (err) { process.exit(2); }
}
try {
  const ast = parser.parse(source, {
    sourceType: 'unambiguous',
    plugins: ['typescript', 'jsx'],
    ecmaVersion: 'latest',
    locations: true
  });
  console.log(JSON.stringify(ast));
} catch (e) {
  process.exit(3);
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as source_file:
        source_file.write(content)
        source_name = source_file.name
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as script_file:
        script_file.write(script)
        script_name = script_file.name
    try:
        result = subprocess.run(
            ["node", script_name, source_name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def analyze_js_taint(content):
    """Basic JS taint tracking with regex fallback when AST parsing is unavailable."""
    parse_js_ast(content)
    tainted = set()
    findings = []

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue

        assignment = re.search(r"\b(?:const|let|var)?\s*(\w+)\s*=\s*(.+)", line)
        if assignment:
            name, expr = assignment.groups()
            if any(source in expr for source in TAINT_SOURCES) or any(var in expr for var in tainted):
                tainted.add(name)

        for sink in SINKS:
            pattern = rf"\b{re.escape(sink)}\s*\(([^)]*)\)"
            match = re.search(pattern, line)
            if not match:
                continue
            arg = match.group(1)
            if any(source in arg for source in TAINT_SOURCES) or any(var in arg for var in tainted):
                findings.append({
                    "line": line_num,
                    "sink": sink,
                    "code": stripped,
                    "message": f"Tainted request data reaches {sink}()",
                })

    return findings
