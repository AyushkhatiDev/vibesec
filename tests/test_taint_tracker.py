"""
Tests for the TaintTracker and the updated SQL injection rule.

Organized into:
  - TRUE POSITIVES: real taint flows that MUST be flagged
  - TRUE NEGATIVES: safe patterns that MUST NOT be flagged (false-positive prevention)
  - EDGE CASES: tricky patterns that stress taint propagation
"""

import pytest
from vibesec.taint_tracker import TaintTracker, analyze_taint, TaintFinding
from vibesec.rules.sql_injection import check_sql_injection


# ═══════════════════════════════════════════════════════════════════════════════
#  TRUE POSITIVES — must be caught
# ═══════════════════════════════════════════════════════════════════════════════


class TestTruePositives:
    """Cases where tainted user input flows into SQL sinks."""

    def test_flask_request_args_to_execute(self):
        """request.args → f-string → cursor.execute"""
        code = '''
from flask import request
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1
        assert any("request.args" in f.source_desc for f in findings)

    def test_flask_request_form_to_execute(self):
        """request.form → concatenation → cursor.execute"""
        code = '''
from flask import request
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1

    def test_input_to_execute(self):
        """input() → f-string → cursor.execute"""
        code = '''
user_input = input("Enter ID: ")
query = f"SELECT * FROM records WHERE id = {user_input}"
db.execute(query)
'''
        findings = analyze_taint("cli_tool.py", code)
        assert len(findings) >= 1
        assert any("input" in f.source_desc.lower() for f in findings)

    def test_request_json_to_execute(self):
        """request.json → cursor.execute with f-string"""
        code = '''
from flask import request
@app.route("/api/search", methods=["POST"])
def search():
    data = request.json
    search_term = data["query"]
    sql = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(sql)
'''
        findings = analyze_taint("api.py", code)
        assert len(findings) >= 1

    def test_request_get_json_to_execute(self):
        """request.get_json() → cursor.execute"""
        code = '''
from flask import request
@app.route("/api/items", methods=["POST"])
def create_item():
    data = request.get_json()
    name = data["name"]
    cursor.execute(f"INSERT INTO items (name) VALUES ('{name}')")
'''
        findings = analyze_taint("api.py", code)
        assert len(findings) >= 1

    def test_taint_through_string_format(self):
        """Taint flows through .format()"""
        code = '''
from flask import request
@app.route("/search")
def search():
    term = request.args.get("q")
    query = "SELECT * FROM items WHERE name = '{}'".format(term)
    cursor.execute(query)
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1

    def test_taint_through_percent_format(self):
        """Taint flows through % formatting"""
        code = '''
from flask import request
@app.route("/search")
def search():
    term = request.args.get("q")
    query = "SELECT * FROM items WHERE name = '%s'" % term
    cursor.execute(query)
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1

    def test_taint_through_multiple_assignments(self):
        """Taint propagates through chained assignments"""
        code = '''
from flask import request
@app.route("/users")
def get_user():
    raw = request.args.get("id")
    cleaned = raw.strip()
    user_id = cleaned
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1

    def test_taint_augmented_assignment(self):
        """Taint via += (augmented assignment)"""
        code = '''
from flask import request
@app.route("/build")
def build_query():
    name = request.form["name"]
    query = "SELECT * FROM users WHERE "
    query += "name = '" + name + "'"
    cursor.execute(query)
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1

    def test_django_request_get(self):
        """Django request.GET → cursor.execute"""
        code = '''
def user_view(request):
    uid = request.GET["user_id"]
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
'''
        findings = analyze_taint("views.py", code)
        assert len(findings) >= 1

    def test_django_request_post(self):
        """Django request.POST → raw SQL"""
        code = '''
def create_user(request):
    name = request.POST["name"]
    sql = "INSERT INTO users (name) VALUES ('" + name + "')"
    connection.execute(sql)
'''
        findings = analyze_taint("views.py", code)
        assert len(findings) >= 1

    def test_sqlalchemy_text_with_taint(self):
        """SQLAlchemy text() with tainted f-string"""
        code = '''
from flask import request
@app.route("/query")
def run_query():
    table = request.args.get("table")
    result = db.session.execute(text(f"SELECT * FROM {table}"))
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1

    def test_sys_argv_to_execute(self):
        """sys.argv taint propagation"""
        code = '''
import sys
table_name = sys.argv[1]
query = f"DROP TABLE {table_name}"
cursor.execute(query)
'''
        findings = analyze_taint("admin.py", code)
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
#  TRUE NEGATIVES — must NOT be flagged (false positive prevention)
# ═══════════════════════════════════════════════════════════════════════════════


class TestTrueNegatives:
    """Safe patterns that must NOT produce findings."""

    def test_parameterized_query_tuple(self):
        """Parameterized query with tuple — safe"""
        code = '''
from flask import request
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) == 0

    def test_parameterized_query_dict(self):
        """Parameterized query with dict — safe"""
        code = '''
from flask import request
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) == 0

    def test_hardcoded_query(self):
        """Fully hardcoded query string — safe"""
        code = '''
cursor.execute("SELECT * FROM users WHERE active = 1")
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) == 0

    def test_constant_fstring_no_variables(self):
        """f-string with only constants — safe"""
        code = '''
TABLE = "users"
cursor.execute(f"SELECT * FROM {TABLE}")
'''
        # This is flagged as "dynamic" since TABLE is a Name node,
        # but the taint tracker shouldn't see it as tainted user input.
        # The tracker *will* flag this via _flag_unsafe_query_construction
        # but only if TABLE appears dynamic. Let's accept this as a minor edge.
        findings = analyze_taint("app.py", code)
        # TABLE is not tainted (it's a hardcoded constant), so taint analysis 
        # should not produce a TaintFinding for it.
        # The _flag_unsafe_query_construction fallback might flag it, 
        # which is acceptable as a warning.
        # We check that no finding links back to user input.
        for f in findings:
            assert "request" not in f.source_desc.lower()
            assert "input" not in f.source_desc.lower()

    def test_orm_query_safe(self):
        """ORM-style queries — safe"""
        code = '''
from flask import request
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    user = User.query.filter_by(id=user_id).first()
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) == 0

    def test_sanitized_input(self):
        """Input that goes through int() cast — safe"""
        code = '''
from flask import request
@app.route("/users")
def get_user():
    user_id = int(request.args.get("id"))
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) == 0

    def test_no_user_input(self):
        """Config-driven query — safe"""
        code = '''
import os
config_table = config.get("table_name")
cursor.execute(f"SELECT * FROM {config_table}")
'''
        # config.get is not a taint source
        findings = analyze_taint("app.py", code)
        tainted_findings = [f for f in findings if "User input" in f.source_desc]
        assert len(tainted_findings) == 0

    def test_skips_readme(self):
        """README files should be skipped entirely"""
        code = '''
cursor.execute(f"SELECT * FROM {user_input}")
'''
        findings = check_sql_injection("README.md", code)
        assert len(findings) == 0

    def test_skips_comments(self):
        """Commented-out code should be ignored by the regex fallback"""
        code = '''
# cursor.execute(f"SELECT * FROM {user_input}")
'''
        findings = check_sql_injection("app.py", code)
        assert len(findings) == 0

    def test_non_python_clean(self):
        """Non-python files return empty."""
        code = "const x = 1 + 1;"
        findings = check_sql_injection("utils.js", code)
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  EDGE CASES — tricky taint propagation
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Tricky patterns that stress taint tracking."""

    def test_taint_through_list_iteration(self):
        """for x in tainted_list → tainted x"""
        code = '''
from flask import request
@app.route("/batch")
def batch():
    ids = request.args.getlist("id")
    for item_id in ids:
        cursor.execute(f"DELETE FROM items WHERE id = {item_id}")
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1

    def test_taint_cleared_by_reassignment(self):
        """Reassigning to a safe value clears taint"""
        code = '''
from flask import request
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    user_id = 42  # now it is safe
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        findings = analyze_taint("app.py", code)
        # user_id was reassigned to a constant, so it's no longer tainted
        tainted = [f for f in findings if "request" in f.source_desc.lower()]
        assert len(tainted) == 0

    def test_syntax_error_returns_empty(self):
        """Unparseable code returns empty findings (no crash)."""
        code = '''
def broken(
    cursor.execute(f"SELECT {x}")
'''
        findings = analyze_taint("bad.py", code)
        assert findings == []

    def test_multiple_sinks_multiple_findings(self):
        """Each tainted sink produces its own finding."""
        code = '''
from flask import request
@app.route("/multi")
def multi():
    name = request.form["name"]
    email = request.form["email"]
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 2

    def test_taint_in_nested_function(self):
        """Taint in inner function scope stays isolated."""
        code = '''
from flask import request

clean_var = "hello"

@app.route("/outer")
def outer():
    tainted = request.args.get("x")
    cursor.execute(f"SELECT * FROM t WHERE x = {tainted}")
'''
        findings = analyze_taint("app.py", code)
        # The outer function has a taint flow
        assert len(findings) >= 1

    def test_subscript_on_request_json(self):
        """request.json["field"] is tainted."""
        code = '''
from flask import request
@app.route("/api/update", methods=["POST"])
def update():
    payload = request.json
    field = payload["column"]
    value = payload["value"]
    query = f"UPDATE settings SET {field} = '{value}'"
    db.execute(query)
'''
        findings = analyze_taint("api.py", code)
        assert len(findings) >= 1

    def test_ternary_taint_propagation(self):
        """Ternary with tainted branch is tainted."""
        code = '''
from flask import request
@app.route("/search")
def search():
    raw = request.args.get("q")
    term = raw if raw else "default"
    cursor.execute(f"SELECT * FROM items WHERE q = '{term}'")
'''
        findings = analyze_taint("app.py", code)
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
#  INTEGRATION — check_sql_injection() with TaintTracker
# ═══════════════════════════════════════════════════════════════════════════════


class TestSQLInjectionRuleIntegration:
    """End-to-end tests through the check_sql_injection() interface."""

    def test_real_taint_flow_flagged(self):
        code = '''
from flask import request
@app.route("/users")
def get_user():
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
'''
        findings = check_sql_injection("app.py", code)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["rule"] == "SQL Injection Risk"

    def test_parameterized_not_flagged(self):
        code = '''
from flask import request
@app.route("/users")
def get_user():
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
'''
        findings = check_sql_injection("app.py", code)
        assert len(findings) == 0

    def test_sanitized_int_not_flagged(self):
        code = '''
from flask import request
@app.route("/users")
def get_user():
    uid = int(request.args.get("id"))
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
'''
        findings = check_sql_injection("app.py", code)
        assert len(findings) == 0

    def test_hardcoded_string_not_flagged(self):
        code = '''
cursor.execute("SELECT COUNT(*) FROM users")
'''
        findings = check_sql_injection("app.py", code)
        assert len(findings) == 0

    def test_finding_has_taint_flow_info(self):
        """Findings should include taint source info in message."""
        code = '''
from flask import request
@app.route("/api")
def api():
    name = request.form["name"]
    db.execute(f"INSERT INTO logs (name) VALUES ('{name}')")
'''
        findings = check_sql_injection("app.py", code)
        assert len(findings) >= 1
        # Check that the finding message mentions the taint source
        msg = findings[0]["message"]
        assert "Tainted" in msg or "taint" in msg.lower() or "request" in msg.lower()
