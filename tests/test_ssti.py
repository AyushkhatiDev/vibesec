from vibesec.rules.ssti import check_ssti


def test_detects_render_template_string_variable():
    assert check_ssti("app.py", "render_template_string(user_template)")


def test_detects_jinja_template_variable():
    assert check_ssti("app.py", "jinja2.Template(user_template)")


def test_detects_template_render_chain():
    assert check_ssti("app.py", "Template(user_template).render()")


def test_allows_hardcoded_template_string():
    assert check_ssti("app.py", 'render_template_string("Hello {{ name }}")') == []


def test_allows_render_template_file():
    assert check_ssti("app.py", 'render_template("index.html", name=user_input)') == []


def test_detects_mako_edge_case():
    assert check_ssti("app.py", "mako.template.Template(user_template)")
