import ast
import re

from vibesec.rules.common import (
    JS_EXTENSIONS,
    PY_EXTENSIONS,
    call_name,
    finding,
    is_comment,
    literal_or_safe_config,
    should_skip_file,
    variable_like,
)

RULE_NAME = "Server-Side Request Forgery"
SEVERITY = "HIGH"
FIX = "Allowlist destination hosts, reject private/link-local ranges, and avoid making requests to user-controlled URLs."

PY_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "urllib.request.urlopen", "urllib.urlopen",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
}


def _unsafe_url_arg(node):
    if node is None or literal_or_safe_config(node):
        return False
    return variable_like(node) is not None


class SSRFVisitor(ast.NodeVisitor):
    def __init__(self, file_path, lines):
        self.file_path = file_path
        self.lines = lines
        self.findings = []

    def visit_Call(self, node):
        name = call_name(node.func)
        first = node.args[0] if node.args else None
        if name in PY_SINKS and _unsafe_url_arg(first):
            self._add(node, f"{name} called with user-controlled URL")
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "post"}:
            receiver = call_name(node.func.value) or ""
            if ("session" in receiver.lower() or "aiohttp" in receiver.lower()) and _unsafe_url_arg(first):
                self._add(node, f"{name} called with user-controlled URL")
        self.generic_visit(node)

    def _add(self, node, message):
        line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        self.findings.append(finding(RULE_NAME, SEVERITY, self.file_path, node.lineno, message, FIX, line))


def _check_python(file_path, content):
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    visitor = SSRFVisitor(file_path, content.splitlines())
    visitor.visit(tree)
    return visitor.findings


def _check_js(file_path, content):
    findings = []
    patterns = [
        (r"\bfetch\s*\(\s*(?![\"'`])", "fetch() called with user-controlled URL"),
        (r"\baxios\.(get|post)\s*\(\s*(?![\"'`])", "axios request called with user-controlled URL"),
        (r"\bhttp\.get\s*\(\s*(?![\"'`])", "http.get() called with user-controlled URL"),
    ]
    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if is_comment(stripped):
            continue
        for pattern, message in patterns:
            if re.search(pattern, line):
                findings.append(finding(RULE_NAME, SEVERITY, file_path, line_num, message, FIX, line))
                break
    return findings


def check_ssrf(file_path, content):
    if should_skip_file(file_path, PY_EXTENSIONS | JS_EXTENSIONS):
        return []
    if file_path.endswith(".py"):
        return _check_python(file_path, content)
    return _check_js(file_path, content)
