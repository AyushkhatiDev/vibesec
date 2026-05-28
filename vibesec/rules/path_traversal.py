import ast
import re

from vibesec.rules.common import (
    JS_EXTENSIONS,
    PY_EXTENSIONS,
    call_name,
    contains_safe_indicator,
    finding,
    is_comment,
    is_string_literal,
    literal_or_safe_config,
    should_skip_file,
    variable_like,
)

RULE_NAME = "Path Traversal"
SEVERITY = "HIGH"
FIX = "Canonicalize and constrain paths to an allowed base directory. Use secure_filename and reject traversal segments."

SAFE_INDICATORS = ("secure_filename", "werkzeug.utils.secure_filename", "safe_join", "Path.resolve")
TAINT_HINTS = ("request.", "req.", "input(", "user", "filename", "path", "file", "params", "query", "body")


def _looks_tainted(node):
    if node is None or literal_or_safe_config(node):
        return False
    text = ast.unparse(node) if hasattr(ast, "unparse") else variable_like(node) or ""
    lower = text.lower()
    return any(hint in lower for hint in TAINT_HINTS) or variable_like(node) is not None


class PathTraversalVisitor(ast.NodeVisitor):
    def __init__(self, file_path, lines):
        self.file_path = file_path
        self.lines = lines
        self.findings = []

    def visit_Call(self, node):
        name = call_name(node.func)
        line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        if contains_safe_indicator(self.lines, node.lineno, SAFE_INDICATORS, window=6):
            self.generic_visit(node)
            return

        first = node.args[0] if node.args else None
        second = node.args[1] if len(node.args) > 1 else None

        if name == "open" and _looks_tainted(first):
            self._add(node, "open() called with user-controlled path")
        elif name in {"send_file", "flask.send_file"} and _looks_tainted(first):
            self._add(node, "send_file() called with user-controlled path")
        elif name in {"send_from_directory", "flask.send_from_directory"} and _looks_tainted(second):
            self._add(node, "send_from_directory() called with user-controlled filename")
        elif name == "os.path.join" and len(node.args) >= 2 and _looks_tainted(node.args[-1]):
            self._add(node, "os.path.join() uses user-controlled path without visible validation")
        elif name in {"Path", "pathlib.Path"} and _looks_tainted(first):
            self._add(node, "pathlib.Path() called with user-controlled path")

        self.generic_visit(node)

    def _add(self, node, message):
        line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        self.findings.append(finding(RULE_NAME, SEVERITY, self.file_path, node.lineno, message, FIX, line))


def _check_python(file_path, content):
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    visitor = PathTraversalVisitor(file_path, content.splitlines())
    visitor.visit(tree)
    return visitor.findings


def _check_js(file_path, content):
    findings = []
    patterns = [
        (r"\bfs\.readFile\s*\(\s*(?![\"'`])", "fs.readFile() called with user-controlled path"),
        (r"\bfs\.readFileSync\s*\(\s*(?![\"'`])", "fs.readFileSync() called with user-controlled path"),
        (r"\bfs\.writeFile\s*\(\s*(?![\"'`])", "fs.writeFile() called with user-controlled path"),
        (r"\bpath\.join\s*\(\s*__dirname\s*,\s*(?![\"'`])", "path.join(__dirname, userInput) may allow traversal"),
        (r"\bres\.sendFile\s*\(\s*(?![\"'`])", "res.sendFile() called with user-controlled path"),
    ]
    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if is_comment(stripped) or contains_safe_indicator(lines, line_num, SAFE_INDICATORS, window=6):
            continue
        for pattern, message in patterns:
            if re.search(pattern, line):
                findings.append(finding(RULE_NAME, SEVERITY, file_path, line_num, message, FIX, line))
                break
    return findings


def check_path_traversal(file_path, content):
    if should_skip_file(file_path, PY_EXTENSIONS | JS_EXTENSIONS):
        return []
    if file_path.endswith(".py"):
        return _check_python(file_path, content)
    return _check_js(file_path, content)
