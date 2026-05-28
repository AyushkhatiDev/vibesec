from vibesec.scanner import Scanner


def test_parallel_scanning_finds_results(tmp_path):
    for index in range(6):
        (tmp_path / f"file{index}.py").write_text('password = "supersecret"', encoding="utf-8")
    scanner = Scanner(str(tmp_path), show_progress=False)
    findings = scanner.run()
    assert len(findings) == 6
    assert scanner.files_scanned == 6
    assert scanner.duration >= 0
