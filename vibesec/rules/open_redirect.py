import ast
import re

from vibesec.rules.common import (
    JS_EXTENSIONS,
    PY_EXTENSIONS,
    call_name,
    contains_safe_indicator,
    finding,
    is_comment,
    literal_or_safe_config,
    should_skip_file,
)

RULE_NAME = "Open Redirect"
SEVERITY = "MEDIUM"
FIX = "Redirect only to known internal routes or validate the destination host against an allowlist."
SAFE_INDICATORS = ("url_for(", "url_parse", "netloc", "allowed_hosts", "is_safe_url", "safe_redirect")


class RedirectVisitor(ast.NodeVisitor):
    def __init__(self, file_path, lines):
        self.file_path = file_path
        self.lines = lines
        self.findings = []

    def visit_Call(self, node):
        name = call_name(node.func)
        first = node.args[0] if node.args else None
        if name in {"redirect", "flask.redirect"} and first:
            if contains_safe_indicator(self.lines, node.lineno, SAFE_INDICATORS, window=6):
                self.generic_visit(node)
                return
            if isinstance(first, ast.Call) and call_name(first.func) in {"url_for", "flask.url_for"}:
                self.generic_visit(node)
                return
            if not literal_or_safe_config(first):
                self._add(node, "redirect() called with user-controlled destination")
        self.generic_visit(node)

    def _add(self, node, message):
        line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        self.findings.append(finding(RULE_NAME, SEVERITY, self.file_path, node.lineno, message, FIX, line))


def _check_python(file_path, content):
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    visitor = RedirectVisitor(file_path, content.splitlines())
    visitor.visit(tree)
    return visitor.findings


def _check_js(file_path, content):
    findings = []
    patterns = [
        (r"\bres\.redirect\s*\(\s*req\.(query|body)\.", "res.redirect() uses request-controlled destination"),
        (r"\b(window|document)\.location(?:\.href)?\s*=\s*(?![\"'`])", "Browser location assigned from dynamic value"),
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


def check_open_redirect(file_path, content):
    if should_skip_file(file_path, PY_EXTENSIONS | JS_EXTENSIONS):
        return []
    if file_path.endswith(".py"):
        return _check_python(file_path, content)
    return _check_js(file_path, content)
