import ast
import os
import re


CODE_EXTENSIONS = {"py", "js", "jsx", "ts", "tsx"}
PY_EXTENSIONS = {"py"}
JS_EXTENSIONS = {"js", "jsx", "ts", "tsx"}
TEST_PATH_PARTS = {"tests", "test", "__tests__", "__mocks__"}


def filename(file_path):
    return file_path.replace("\\", "/").rsplit("/", 1)[-1]


def extension(file_path):
    name = filename(file_path)
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def normalized_path(file_path):
    return file_path.replace("\\", "/")


def is_test_path(file_path):
    path = normalized_path(file_path)
    name = filename(file_path)
    parts = {part.lower() for part in path.split("/")}
    return (
        bool(TEST_PATH_PARTS & parts)
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.js")
        or name.endswith(".test.ts")
        or name.endswith(".spec.js")
        or name.endswith(".spec.ts")
    )


def should_skip_file(file_path, extensions=None, skip_tests=True):
    name = filename(file_path)
    if name.lower() in {"readme.md", "license"}:
        return True
    if skip_tests and is_test_path(file_path):
        return True
    if extensions is not None and extension(file_path) not in extensions:
        return True
    return False


def is_comment(stripped):
    return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("--")


def finding(rule, severity, file_path, line, message, fix_hint, code):
    return {
        "rule": rule,
        "severity": severity,
        "file": file_path,
        "line": line,
        "message": message,
        "fix_hint": fix_hint,
        "code_snippet": code.strip()[:120],
    }


def surrounding_lines(lines, line_num, window=5):
    start = max(0, line_num - window - 1)
    end = min(len(lines), line_num + window)
    return "\n".join(lines[start:end])


def contains_safe_indicator(lines, line_num, indicators, window=5):
    surrounding = surrounding_lines(lines, line_num, window)
    return any(indicator in surrounding for indicator in indicators)


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    return None


def is_string_literal(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_bytes_literal(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, (bytes, bytearray))


def is_list_literal(node):
    return isinstance(node, (ast.List, ast.Tuple))


def literal_or_safe_config(node):
    if is_string_literal(node) or is_bytes_literal(node):
        return True
    if isinstance(node, ast.Call):
        name = call_name(node.func)
        if name in {"os.environ.get", "os.getenv", "settings.get", "config.get"}:
            return True
    if isinstance(node, ast.Subscript):
        name = call_name(node.value)
        if name in {"os.environ", "config", "settings"}:
            return True
    return False


def variable_like(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return call_name(node)
    if isinstance(node, ast.Subscript):
        return call_name(node.value) or "subscript"
    if isinstance(node, ast.JoinedStr):
        return "f-string"
    if isinstance(node, ast.BinOp):
        return "dynamic expression"
    if isinstance(node, ast.Call):
        return call_name(node.func) or "call"
    return None


def has_keyword(node, key, value=True):
    for keyword in getattr(node, "keywords", []):
        if keyword.arg == key and isinstance(keyword.value, ast.Constant):
            return keyword.value.value is value
    return False


def keyword_name(node, key):
    for keyword in getattr(node, "keywords", []):
        if keyword.arg == key:
            return call_name(keyword.value) or getattr(keyword.value, "id", None)
    return None


def line_has_assignment_to(line, terms):
    return any(re.search(rf"\b{re.escape(term)}\b\s*=", line) for term in terms)


def has_dockerignore(file_path):
    path = normalized_path(file_path)
    directory = os.path.dirname(path) or "."
    return os.path.exists(os.path.join(directory, ".dockerignore"))
