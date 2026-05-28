from vibesec.rules.open_redirect import check_open_redirect


def test_detects_redirect_request_args():
    assert check_open_redirect("app.py", "redirect(request.args.get('next'))")


def test_detects_return_redirect_user_input():
    assert check_open_redirect("app.py", "return redirect(next_url)")


def test_detects_js_res_redirect():
    assert check_open_redirect("app.js", "res.redirect(req.query.url)")


def test_allows_url_for():
    assert check_open_redirect("app.py", "redirect(url_for('home'))") == []


def test_allows_validated_url_nearby():
    content = "parsed = url_parse(next_url)\nif parsed.netloc == '':\n    return redirect(next_url)"
    assert check_open_redirect("app.py", content) == []


def test_detects_window_location_edge_case():
    assert check_open_redirect("app.js", "window.location.href = redirectUrl")
