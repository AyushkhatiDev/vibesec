import ast

from vibesec.rules.common import PY_EXTENSIONS, call_name, finding, is_string_literal, should_skip_file

RULE_NAME = "Server-Side Template Injection"
SEVERITY = "CRITICAL"
FIX = "Render fixed template files and pass user input as variables. Do not compile user-controlled template strings."


class SSTIVisitor(ast.NodeVisitor):
    def __init__(self, file_path, lines):
        self.file_path = file_path
        self.lines = lines
        self.findings = []

    def visit_Call(self, node):
        name = call_name(node.func)
        first = node.args[0] if node.args else None

        if name in {"render_template_string", "flask.render_template_string"}:
            if first and not is_string_literal(first):
                self._add(node, "render_template_string() called with dynamic template")
            elif isinstance(first, ast.JoinedStr):
                self._add(node, "render_template_string() called with f-string template")
        elif name in {"Template", "jinja2.Template", "mako.template.Template"} and first and not is_string_literal(first):
            self._add(node, f"{name} compiles a dynamic template")
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "render":
            parent = node.func.value
            if isinstance(parent, ast.Call) and call_name(parent.func) in {"Template", "jinja2.Template"}:
                first_parent = parent.args[0] if parent.args else None
                if first_parent and not is_string_literal(first_parent):
                    self._add(node, "Template(user_input).render() may allow SSTI")

        self.generic_visit(node)

    def _add(self, node, message):
        line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        self.findings.append(finding(RULE_NAME, SEVERITY, self.file_path, node.lineno, message, FIX, line))


def check_ssti(file_path, content):
    if should_skip_file(file_path, PY_EXTENSIONS):
        return []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    visitor = SSTIVisitor(file_path, content.splitlines())
    visitor.visit(tree)
    return visitor.findings
