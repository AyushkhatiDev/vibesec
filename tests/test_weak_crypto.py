from vibesec.rules.weak_crypto import check_weak_crypto


def test_detects_md5_low():
    findings = check_weak_crypto("app.py", "hashlib.md5(data).hexdigest()")
    assert findings and findings[0]["severity"] == "LOW"


def test_detects_sha1_high():
    findings = check_weak_crypto("app.py", "hashlib.sha1(data).hexdigest()")
    assert findings and findings[0]["severity"] == "HIGH"


def test_detects_js_md5():
    assert check_weak_crypto("app.js", "crypto.createHash('md5')")


def test_allows_secrets_token_hex():
    assert check_weak_crypto("app.py", "token = secrets.token_hex(32)") == []


def test_allows_sha256():
    assert check_weak_crypto("app.py", "hashlib.sha256(data).hexdigest()") == []


def test_detects_random_token_edge_case():
    assert check_weak_crypto("app.py", "token = random.randint(1, 999999)")
