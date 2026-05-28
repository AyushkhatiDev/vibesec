from vibesec.rules.ssrf import check_ssrf


def test_detects_requests_get_variable():
    assert check_ssrf("app.py", "requests.get(url)")


def test_detects_urllib_urlopen():
    assert check_ssrf("app.py", "urllib.request.urlopen(request.args.get('url'))")


def test_detects_js_fetch():
    assert check_ssrf("app.js", "fetch(req.query.url)")


def test_allows_hardcoded_url():
    assert check_ssrf("app.py", 'requests.get("https://api.example.com")') == []


def test_allows_env_url():
    assert check_ssrf("app.py", 'requests.get(os.environ.get("API_URL"))') == []


def test_detects_aiohttp_session_edge_case():
    assert check_ssrf("app.py", "session.get(user_url)")
