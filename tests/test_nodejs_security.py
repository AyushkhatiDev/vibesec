from vibesec.rules.nodejs_security import check_nodejs_security


def test_detects_missing_helmet():
    assert check_nodejs_security("server.js", "const app = express()")


def test_detects_insecure_cookie():
    assert check_nodejs_security("server.js", "res.cookie('sid', token)")


def test_detects_prototype_pollution_merge():
    assert check_nodejs_security("server.js", "_.merge({}, req.body)")


def test_allows_helmet_setup():
    content = "const helmet = require('helmet')\nconst app = express()\napp.use(helmet())"
    assert not any("helmet" in f["message"] for f in check_nodejs_security("server.js", content))


def test_allows_hardened_cookie():
    content = "res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'strict' })"
    assert check_nodejs_security("handler.js", content) == []


def test_detects_missing_rate_limit_edge_case():
    assert any("rate" in f["message"] for f in check_nodejs_security("server.js", "const app = express()\napp.get('/api/users', h)"))
