from vibesec.rules.path_traversal import check_path_traversal


def test_detects_open_user_path():
    assert check_path_traversal("app.py", "open(request.args.get('file'))")


def test_detects_send_file_user_path():
    assert check_path_traversal("app.py", "send_file(user_path)")


def test_detects_js_readfile():
    assert check_path_traversal("app.js", "fs.readFile(req.query.file, cb)")


def test_allows_secure_filename_nearby():
    content = "from werkzeug.utils import secure_filename\nfilename = secure_filename(name)\nopen(os.path.join(SAFE_DIR, filename))"
    assert check_path_traversal("app.py", content) == []


def test_allows_literal_open():
    assert check_path_traversal("app.py", 'open("static/index.html")') == []


def test_detects_path_join_edge_case():
    assert check_path_traversal("app.py", "os.path.join(BASE_DIR, filename)")
