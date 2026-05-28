from vibesec.rules.command_injection import check_command_injection


def test_detects_os_system_variable():
    assert check_command_injection("app.py", "os.system(cmd)")


def test_detects_subprocess_shell_true():
    assert check_command_injection("app.py", "subprocess.run(cmd, shell=True)")


def test_detects_js_exec():
    assert check_command_injection("app.js", "child_process.exec(req.body.cmd)")


def test_allows_literal_os_system():
    assert check_command_injection("app.py", 'os.system("git status")') == []


def test_allows_subprocess_list_form():
    assert check_command_injection("app.py", 'subprocess.run(["npm", "install", package])') == []


def test_detects_dynamic_eval_edge_case():
    assert check_command_injection("app.py", "eval(user_code)")
