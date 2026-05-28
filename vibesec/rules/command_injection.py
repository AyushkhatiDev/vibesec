import ast
import re

from vibesec.rules.common import (
    JS_EXTENSIONS,
    PY_EXTENSIONS,
    call_name,
    finding,
    has_keyword,
    is_comment,
    is_list_literal,
    is_string_literal,
    should_skip_file,
)

RULE_NAME = "Command Injection"

PY_FIX = "Avoid shell execution with user-controlled input. Use argument lists with shell=False and validate allowed commands."
JS_FIX = "Avoid child_process exec with user-controlled input. Use spawn/execFile with fixed commands and argument arrays."


class CommandInjectionVisitor(ast.NodeVisitor):
    def __init__(self, file_path, lines):
        self.file_path = file_path
        self.lines = lines
        self.findings = []

    def visit_Call(self, node):
        name = call_name(node.func)
        first = node.args[0] if node.args else None
        line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""

        if name in {"os.system", "os.popen"} and first and not is_string_literal(first):
            self._add(node, f"{name} called with dynamic command")
        elif name in {"eval", "exec"} and first and not is_string_literal(first):
            self._add(node, f"{name} called with dynamic code")
        elif name in {"subprocess.call", "subprocess.run", "subprocess.Popen"}:
            if has_keyword(node, "shell", True) and first and not is_string_literal(first):
                self._add(node, f"{name} called with shell=True and dynamic command")
            elif has_keyword(node, "shell", True) and first and is_string_literal(first):
                self._add(node, f"{name} called with shell=True")

        self.generic_visit(node)

    def _add(self, node, message):
        line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        self.findings.append(finding(
            RULE_NAME, "CRITICAL", self.file_path, node.lineno, message, PY_FIX, line
        ))


def _check_python(file_path, content):
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _check_python_regex(file_path, content)
    visitor = CommandInjectionVisitor(file_path, content.splitlines())
    visitor.visit(tree)
    return visitor.findings


def _check_python_regex(file_path, content):
    findings = []
    patterns = [
        (r"\bos\.system\s*\(\s*(?![rubf]*[\"'])", "os.system called with dynamic command"),
        (r"\bos\.popen\s*\(\s*(?![rubf]*[\"'])", "os.popen called with dynamic command"),
        (r"\b(eval|exec)\s*\(\s*(?![rubf]*[\"'])", "Dynamic eval/exec call"),
        (r"\bsubprocess\.(call|run|Popen)\s*\([^,\n]+,\s*shell\s*=\s*True", "subprocess shell=True with dynamic command"),
    ]
    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if is_comment(stripped):
            continue
        if "subprocess.run([" in line and "shell=True" not in line:
            continue
        for pattern, message in patterns:
            if re.search(pattern, line):
                findings.append(finding(RULE_NAME, "CRITICAL", file_path, line_num, message, PY_FIX, line))
                break
    return findings


def _check_js(file_path, content):
    findings = []
    patterns = [
        (r"\b(?:child_process\.)?exec\s*\(\s*(?![\"'`])", "child_process.exec called with dynamic command"),
        (r"\b(?:child_process\.)?execSync\s*\(\s*(?![\"'`])", "child_process.execSync called with dynamic command"),
        (r"\b(?:child_process\.)?spawn\s*\([^,\n]+,\s*\{[^}]*shell\s*:\s*true", "child_process.spawn called with shell=true"),
    ]
    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if is_comment(stripped):
            continue
        for pattern, message in patterns:
            if re.search(pattern, line):
                findings.append(finding(RULE_NAME, "CRITICAL", file_path, line_num, message, JS_FIX, line))
                break
    return findings


def check_command_injection(file_path, content):
    if should_skip_file(file_path, PY_EXTENSIONS | JS_EXTENSIONS):
        return []
    if file_path.endswith(".py"):
        return _check_python(file_path, content)
    return _check_js(file_path, content)
