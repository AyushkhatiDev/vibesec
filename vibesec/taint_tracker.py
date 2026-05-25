"""
TaintTracker — Intraprocedural taint analysis for Python source code.

Tracks data flow from user-controlled sources (request.args, input(), etc.)
through assignments and string operations to SQL sinks (cursor.execute, etc.).
Only flags SQL injection when tainted data actually reaches a dangerous sink.
"""

import ast
import os
from typing import Dict, List, Optional, Set, Tuple


# ─── Taint Sources ───────────────────────────────────────────────────────────
# Attribute-style sources: obj.attr  (e.g. request.args, request.form)
TAINT_SOURCE_ATTRS = {
    # Flask / Django request
    ("request", "args"),
    ("request", "form"),
    ("request", "values"),
    ("request", "json"),
    ("request", "data"),
    ("request", "files"),
    ("request", "headers"),
    ("request", "cookies"),
    ("request", "query_string"),
    ("request", "get_json"),
    # Django
    ("request", "GET"),
    ("request", "POST"),
    ("request", "body"),
    ("request", "META"),
    # FastAPI / Starlette
    ("request", "query_params"),
    ("request", "path_params"),
    ("request", "form_data"),
}

# Call-style sources: func(...)  (e.g. input(), sys.stdin.read())
TAINT_SOURCE_CALLS = {
    "input",
}

# Full dotted call sources
TAINT_SOURCE_DOTTED_CALLS = {
    "sys.stdin.read",
    "sys.stdin.readline",
    "request.get_json",
    "request.get_data",
}

# Subscript sources: obj[key] or obj.get(key)
TAINT_SOURCE_SUBSCRIPTS = {
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.headers",
    "request.cookies",
    "request.GET",
    "request.POST",
    "os.environ",
    "sys.argv",
}

# sys.argv is taint
TAINT_SOURCE_NAMES = {
    "sys.argv",
}

# ─── SQL Sinks ───────────────────────────────────────────────────────────────
# method names that execute raw SQL
SQL_SINK_METHODS = {
    "execute",
    "executemany",
    "executescript",
    "raw",
    "execute_sql",
}

# Full dotted sinks
SQL_SINK_DOTTED = {
    "cursor.execute",
    "cursor.executemany",
    "db.execute",
    "db.engine.execute",
    "connection.execute",
    "conn.execute",
    "session.execute",
    "db.session.execute",
    "cr.execute",
}

# Functions that when called with a tainted arg are sinks
SQL_SINK_FUNCS = {
    "text",  # sqlalchemy text()
}

# ─── Sanitizers ──────────────────────────────────────────────────────────────
# Functions/methods that sanitize taint (output is safe)
SANITIZERS = {
    "escape",
    "quote",
    "parameterize",
    "sanitize",
    "clean",
    "bleach.clean",
    "html.escape",
    "markupsafe.escape",
    "int",
    "float",
    "bool",
    "str.isdigit",
    "str.isalnum",
    "validate",
}


class TaintedVar:
    """Represents a tainted variable with source provenance."""

    __slots__ = ("name", "source_line", "source_desc")

    def __init__(self, name: str, source_line: int, source_desc: str):
        self.name = name
        self.source_line = source_line
        self.source_desc = source_desc

    def __repr__(self):
        return f"TaintedVar({self.name!r}, line={self.source_line})"


class TaintFinding:
    """A confirmed taint-flow finding: source → sink."""

    __slots__ = (
        "sink_line", "sink_code", "source_line", "source_desc",
        "sink_desc", "tainted_var",
    )

    def __init__(
        self,
        sink_line: int,
        sink_code: str,
        source_line: int,
        source_desc: str,
        sink_desc: str,
        tainted_var: str,
    ):
        self.sink_line = sink_line
        self.sink_code = sink_code
        self.source_line = source_line
        self.source_desc = source_desc
        self.sink_desc = sink_desc
        self.tainted_var = tainted_var


# ─── AST Helpers ─────────────────────────────────────────────────────────────

def _dotted_name(node: ast.AST) -> Optional[str]:
    """Extract dotted name from an AST node, e.g. request.args → 'request.args'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
    return None


def _get_call_name(node: ast.Call) -> Optional[str]:
    """Get the full dotted name of a function call."""
    return _dotted_name(node.func)


def _get_assigned_names(target: ast.AST) -> List[str]:
    """Extract variable names from an assignment target."""
    names = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
        for elt in target.elts:
            names.extend(_get_assigned_names(elt))
    elif isinstance(target, ast.Starred):
        names.extend(_get_assigned_names(target.value))
    return names


def _source_line(node: ast.AST) -> int:
    """Get the line number of an AST node."""
    return getattr(node, "lineno", 0)


# ─── Core Taint Tracker ─────────────────────────────────────────────────────

class TaintTracker(ast.NodeVisitor):
    """
    Intraprocedural taint tracker for a single Python file.
    
    Walks the AST and:
      1. Identifies taint sources (user input)
      2. Propagates taint through assignments and expressions
      3. Detects when tainted data flows into SQL sinks
    
    Operates per-function scope: taint does not leak across function boundaries.
    For global-scope code, it tracks taint at module level.
    """

    def __init__(self, source_code: str, file_path: str = "<unknown>"):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[TaintFinding] = []

        # Per-scope taint state: var_name → TaintedVar
        self._scope_stack: List[Dict[str, TaintedVar]] = [{}]

        # Track function parameters that should be considered tainted
        # (params to route handlers)
        self._route_handler_params: Set[str] = set()

    @property
    def _tainted(self) -> Dict[str, TaintedVar]:
        """Current scope's tainted variables."""
        return self._scope_stack[-1]

    def _push_scope(self):
        """Enter a new scope (copies parent taint for closures)."""
        self._scope_stack.append(dict(self._scope_stack[-1]))

    def _pop_scope(self):
        """Leave a scope."""
        if len(self._scope_stack) > 1:
            self._scope_stack.pop()

    def _mark_tainted(self, name: str, line: int, desc: str):
        """Mark a variable as tainted."""
        self._tainted[name] = TaintedVar(name, line, desc)

    def _is_tainted(self, name: str) -> bool:
        """Check if a variable is tainted in the current scope."""
        return name in self._tainted

    def _get_taint(self, name: str) -> Optional[TaintedVar]:
        """Get taint info for a variable."""
        return self._tainted.get(name)

    def _clear_taint(self, name: str):
        """Remove taint from a variable (e.g., after sanitization)."""
        self._tainted.pop(name, None)

    def _get_line_text(self, lineno: int) -> str:
        """Get source text for a line number."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    # ─── Expression Taint Evaluation ─────────────────────────────────

    def _expr_is_tainted(self, node: ast.AST) -> Optional[TaintedVar]:
        """
        Check if an expression is tainted. Returns TaintedVar if tainted, None otherwise.
        Recursively checks sub-expressions.
        """
        if node is None:
            return None

        # Variable reference
        if isinstance(node, ast.Name):
            return self._get_taint(node.id)

        # Attribute access: check if it's a taint source or tainted obj
        if isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            if dotted:
                # Check full dotted name
                t = self._get_taint(dotted)
                if t:
                    return t
                # Check if it's a known taint source attribute
                if isinstance(node.value, ast.Name):
                    pair = (node.value.id, node.attr)
                    if pair in TAINT_SOURCE_ATTRS:
                        tv = TaintedVar(
                            dotted, _source_line(node),
                            f"User input via {dotted}"
                        )
                        return tv
                # Check if parent is tainted
                parent_taint = self._expr_is_tainted(node.value)
                if parent_taint:
                    return parent_taint

        # Subscript: e.g. request.args["key"] or data["field"]
        if isinstance(node, ast.Subscript):
            val_dotted = _dotted_name(node.value)
            if val_dotted and val_dotted in TAINT_SOURCE_SUBSCRIPTS:
                return TaintedVar(
                    val_dotted, _source_line(node),
                    f"User input via {val_dotted}[...]"
                )
            # If the value being subscripted is tainted, subscript result is tainted
            parent_taint = self._expr_is_tainted(node.value)
            if parent_taint:
                return parent_taint

        # Function calls
        if isinstance(node, ast.Call):
            call_name = _get_call_name(node)

            # Check sanitizers first — sanitized output is NOT tainted
            if call_name and self._is_sanitizer(call_name):
                return None

            # Check if it's a taint source call
            if call_name:
                if call_name in TAINT_SOURCE_CALLS:
                    return TaintedVar(
                        call_name, _source_line(node),
                        f"User input via {call_name}()"
                    )
                if call_name in TAINT_SOURCE_DOTTED_CALLS:
                    return TaintedVar(
                        call_name, _source_line(node),
                        f"User input via {call_name}()"
                    )
                # .get() on taint source: request.args.get("key")
                if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                    parent_dotted = _dotted_name(node.func.value)
                    if parent_dotted and parent_dotted in TAINT_SOURCE_SUBSCRIPTS:
                        return TaintedVar(
                            parent_dotted, _source_line(node),
                            f"User input via {parent_dotted}.get(...)"
                        )
                # .getlist() on taint source: request.args.getlist("key")
                if isinstance(node.func, ast.Attribute) and node.func.attr == "getlist":
                    parent_dotted = _dotted_name(node.func.value)
                    if parent_dotted and parent_dotted in TAINT_SOURCE_SUBSCRIPTS:
                        return TaintedVar(
                            parent_dotted, _source_line(node),
                            f"User input via {parent_dotted}.getlist(...)"
                        )

            # Method call on a tainted receiver: tainted_obj.method()
            # e.g. raw.strip(), raw.lower(), data.decode()
            if isinstance(node.func, ast.Attribute):
                receiver_taint = self._expr_is_tainted(node.func.value)
                if receiver_taint:
                    return receiver_taint

            # If any argument to a non-sanitizer call is tainted,
            # the return value is conservatively tainted
            for arg in node.args:
                t = self._expr_is_tainted(arg)
                if t:
                    return t
            for kw in node.keywords:
                t = self._expr_is_tainted(kw.value)
                if t:
                    return t

        # String concatenation: BinOp with Add or Mod
        if isinstance(node, ast.BinOp):
            left_t = self._expr_is_tainted(node.left)
            if left_t:
                return left_t
            right_t = self._expr_is_tainted(node.right)
            if right_t:
                return right_t

        # F-string (JoinedStr)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    t = self._expr_is_tainted(value.value)
                    if t:
                        return t

        # String .format() call
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Attribute) and
                    node.func.attr == "format"):
                for arg in node.args:
                    t = self._expr_is_tainted(arg)
                    if t:
                        return t
                for kw in node.keywords:
                    t = self._expr_is_tainted(kw.value)
                    if t:
                        return t

        # % formatting: "... %s ..." % value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            right_t = self._expr_is_tainted(node.right)
            if right_t:
                return right_t

        # Ternary / IfExp: tainted if either branch is tainted
        if isinstance(node, ast.IfExp):
            t = self._expr_is_tainted(node.body)
            if t:
                return t
            t = self._expr_is_tainted(node.orelse)
            if t:
                return t

        # Tuple/List/Set literals — tainted if any element is tainted
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for elt in node.elts:
                t = self._expr_is_tainted(elt)
                if t:
                    return t

        # Dict — tainted if any value is tainted
        if isinstance(node, ast.Dict):
            for v in node.values:
                if v is not None:
                    t = self._expr_is_tainted(v)
                    if t:
                        return t

        return None

    def _is_sanitizer(self, call_name: str) -> bool:
        """Check if a call is a known sanitizer."""
        if call_name in SANITIZERS:
            return True
        # Also check the last part (method name)
        parts = call_name.rsplit(".", 1)
        if len(parts) == 2 and parts[1] in SANITIZERS:
            return True
        return False

    # ─── Sink Detection ──────────────────────────────────────────────

    def _check_sql_sink(self, node: ast.Call):
        """
        Check if a Call node is a SQL sink receiving tainted data.
        
        We check:
          1. cursor.execute(query) / db.execute(query) — method calls
          2. text(query) — SQLAlchemy text()
          
        The first positional arg is the SQL query. If it's tainted,
        it's a finding. If it's a string literal (no interpolation),
        it's safe.
        """
        call_name = _get_call_name(node)
        if not call_name:
            return

        is_sql_sink = False
        sink_desc = ""

        # Method-style sinks: cursor.execute(...), db.execute(...)
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method in SQL_SINK_METHODS:
                is_sql_sink = True
                sink_desc = f"{call_name}()"

        # Dotted sinks
        if call_name in SQL_SINK_DOTTED:
            is_sql_sink = True
            sink_desc = f"{call_name}()"

        # Function sinks: text(...)
        if call_name in SQL_SINK_FUNCS:
            is_sql_sink = True
            sink_desc = f"{call_name}()"

        if not is_sql_sink:
            return

        # The first positional argument is the SQL query
        if not node.args:
            return

        query_arg = node.args[0]

        # If it's a plain string constant, it's parameterized — SAFE
        if isinstance(query_arg, ast.Constant) and isinstance(query_arg.value, str):
            return

        # If it's a Name pointing to a string constant, also safe
        # (we can't easily track this, so we check taint instead)

        # Check if the query argument is tainted
        taint = self._expr_is_tainted(query_arg)
        if taint:
            self.findings.append(TaintFinding(
                sink_line=_source_line(node),
                sink_code=self._get_line_text(_source_line(node)),
                source_line=taint.source_line,
                source_desc=taint.source_desc,
                sink_desc=f"SQL query passed to {sink_desc}",
                tainted_var=taint.name,
            ))
            return

        # Even without taint tracking, flag f-strings and concatenation in the
        # query arg itself (these are inherently suspicious in SQL context)
        if isinstance(query_arg, ast.JoinedStr):
            # F-string — check if any interpolated value is tainted
            # If no taint was found above, it might be a constant interpolation
            # Still flag it as risky since f-strings in SQL are almost always wrong
            self._flag_unsafe_query_construction(node, query_arg, "f-string")
        elif isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Add):
            self._flag_unsafe_query_construction(node, query_arg, "string concatenation")
        elif isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Mod):
            self._flag_unsafe_query_construction(node, query_arg, "% formatting")

    def _flag_unsafe_query_construction(
        self, call_node: ast.Call, query_node: ast.AST, method: str
    ):
        """
        Flag cases where SQL queries are built with string interpolation,
        even if we can't confirm taint. These are *always* suspicious.
        But we only flag them if variable names are involved that are
        NOT known to be clean (i.e., we check the scope for taint info).
        """
        # Check if any Name nodes in the query expression could be dynamic
        # and are not known-clean variables in the current scope
        has_risky_dynamic = False
        for child in ast.walk(query_node):
            if isinstance(child, ast.Name):
                # Skip common safe constants
                if child.id in {"True", "False", "None"}:
                    continue
                # If the variable is known in scope and NOT tainted, it's safe
                # If it IS tainted, we would have caught it in the taint check above
                # If it's unknown, it's potentially risky
                if child.id not in self._tainted:
                    # Unknown origin — conservatively risky only if we
                    # haven't seen a clean assignment to it in this scope.
                    # But since visit_Assign clears taint on clean assignment,
                    # if it's in scope at all it went through assignment.
                    # If not in _tainted dict at all, it was never tainted,
                    # which means it was assigned a clean value or is a constant.
                    pass  # known clean or constant — skip
                else:
                    has_risky_dynamic = True
                    break
            if isinstance(child, ast.Call):
                # Function call in SQL — check if any arg is tainted
                for arg_child in ast.walk(child):
                    if isinstance(arg_child, ast.Name) and self._is_tainted(arg_child.id):
                        has_risky_dynamic = True
                        break
                if has_risky_dynamic:
                    break
            if isinstance(child, ast.Subscript):
                val_taint = self._expr_is_tainted(child)
                if val_taint:
                    has_risky_dynamic = True
                    break
            if isinstance(child, ast.Attribute):
                val_taint = self._expr_is_tainted(child)
                if val_taint:
                    has_risky_dynamic = True
                    break

        if has_risky_dynamic:
            self.findings.append(TaintFinding(
                sink_line=_source_line(call_node),
                sink_code=self._get_line_text(_source_line(call_node)),
                source_line=_source_line(query_node),
                source_desc=f"Dynamic value in SQL via {method}",
                sink_desc=f"SQL query built with {method}",
                tainted_var="<dynamic>",
            ))

    # ─── AST Visitor Methods ─────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit a function definition — new scope."""
        self._push_scope()

        # Check if this is a route handler (has route-like decorators)
        is_route_handler = False
        for decorator in node.decorator_list:
            dec_name = _dotted_name(decorator) if not isinstance(decorator, ast.Call) else None
            if dec_name is None and isinstance(decorator, ast.Call):
                dec_name = _dotted_name(decorator.func)
            if dec_name and any(kw in dec_name for kw in ("route", "get", "post", "put", "delete", "patch", "api_view")):
                is_route_handler = True
                break

        # If route handler, mark all params (except self/cls) as potentially tainted
        if is_route_handler:
            for arg in node.args.args:
                if arg.arg not in ("self", "cls"):
                    self._mark_tainted(
                        arg.arg, _source_line(node),
                        f"Route handler parameter '{arg.arg}'"
                    )

        self.generic_visit(node)
        self._pop_scope()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign):
        """Track taint propagation through assignments."""
        # Check if RHS is tainted
        rhs_taint = self._expr_is_tainted(node.value)

        for target in node.targets:
            names = _get_assigned_names(target)
            for name in names:
                if rhs_taint:
                    self._mark_tainted(name, rhs_taint.source_line, rhs_taint.source_desc)
                else:
                    # Assignment of a clean value clears taint
                    self._clear_taint(name)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Annotated assignment: x: str = tainted_value."""
        if node.value and node.target:
            rhs_taint = self._expr_is_tainted(node.value)
            names = _get_assigned_names(node.target)
            for name in names:
                if rhs_taint:
                    self._mark_tainted(name, rhs_taint.source_line, rhs_taint.source_desc)
                else:
                    self._clear_taint(name)

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """Augmented assignment: x += tainted_value."""
        rhs_taint = self._expr_is_tainted(node.value)
        if rhs_taint:
            names = _get_assigned_names(node.target)
            for name in names:
                self._mark_tainted(name, rhs_taint.source_line, rhs_taint.source_desc)

        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        """For loop: for x in tainted_iter."""
        iter_taint = self._expr_is_tainted(node.iter)
        if iter_taint:
            names = _get_assigned_names(node.target)
            for name in names:
                self._mark_tainted(name, iter_taint.source_line, iter_taint.source_desc)

        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        """With statement: with tainted as x."""
        for item in node.items:
            if item.optional_vars:
                ctx_taint = self._expr_is_tainted(item.context_expr)
                if ctx_taint:
                    names = _get_assigned_names(item.optional_vars)
                    for name in names:
                        self._mark_tainted(name, ctx_taint.source_line, ctx_taint.source_desc)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check every call for SQL sinks."""
        self._check_sql_sink(node)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        """Expression statement — check if it's a sink call."""
        self.generic_visit(node)

    # ─── Public API ──────────────────────────────────────────────────

    def analyze(self) -> List[TaintFinding]:
        """
        Parse and analyze the source code.
        Returns a list of TaintFinding objects.
        """
        try:
            tree = ast.parse(self.source_code, filename=self.file_path)
        except SyntaxError:
            # Can't parse — fall back to no findings (regex rule will still catch obvious stuff)
            return []

        self.visit(tree)
        return self.findings


# ─── Public Interface ────────────────────────────────────────────────────────

def analyze_taint(file_path: str, content: str) -> List[TaintFinding]:
    """
    Run taint analysis on Python source code.
    
    Args:
        file_path: Path to the file (for reporting).
        content: The source code to analyze.
    
    Returns:
        List of TaintFinding objects.
    """
    tracker = TaintTracker(content, file_path)
    return tracker.analyze()
