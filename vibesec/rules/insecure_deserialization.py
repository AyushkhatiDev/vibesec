import ast

from vibesec.rules.common import (
    PY_EXTENSIONS,
    call_name,
    finding,
    is_bytes_literal,
    literal_or_safe_config,
    should_skip_file,
)

RULE_NAME = "Insecure Deserialization"
FIX = "Use safe formats such as JSON for untrusted data. For YAML use yaml.safe_load or SafeLoader."


class DeserializationVisitor(ast.NodeVisitor):
    def __init__(self, file_path, lines):
        self.file_path = file_path
        self.lines = lines
        self.findings = []

    def visit_Call(self, node):
        name = call_name(node.func)
        first = node.args[0] if node.args else None

        if name in {"pickle.loads", "pickle.load"}:
            if not (name == "pickle.loads" and is_bytes_literal(first)):
                self._add(node, "CRITICAL", f"{name} deserializes potentially untrusted data")
        elif name == "marshal.loads" and not literal_or_safe_config(first):
            self._add(node, "CRITICAL", "marshal.loads() deserializes potentially untrusted data")
        elif name == "shelve.open" and not literal_or_safe_config(first):
            self._add(node, "CRITICAL", "shelve.open() uses a user-controlled shelf path")
        elif name == "yaml.load":
            loader = None
            for keyword in node.keywords:
                if keyword.arg in {"Loader", "loader"}:
                    loader = call_name(keyword.value)
                    break
            if loader in {"yaml.SafeLoader", "SafeLoader"}:
                pass
            elif loader in {None, "yaml.Loader", "Loader"}:
                self._add(node, "HIGH", "yaml.load() uses an unsafe loader")

        self.generic_visit(node)

    def _add(self, node, severity, message):
        line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        self.findings.append(finding(RULE_NAME, severity, self.file_path, node.lineno, message, FIX, line))


def check_insecure_deserialization(file_path, content):
    if should_skip_file(file_path, PY_EXTENSIONS):
        return []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    visitor = DeserializationVisitor(file_path, content.splitlines())
    visitor.visit(tree)
    return visitor.findings
