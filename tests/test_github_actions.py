from vibesec.rules.github_actions import check_github_actions


PATH = "repo/.github/workflows/ci.yml"


def test_detects_unpinned_action():
    assert check_github_actions(PATH, "steps:\n  - uses: actions/checkout@main")


def test_detects_script_injection():
    assert check_github_actions(PATH, 'run: echo "${{ github.event.issue.title }}"')


def test_detects_write_all():
    assert check_github_actions(PATH, "permissions: write-all")


def test_allows_sha_pinned_action():
    sha = "a" * 40
    assert check_github_actions(PATH, f"steps:\n  - uses: actions/checkout@{sha}") == []


def test_skips_non_workflow():
    assert check_github_actions("ci.yml", "permissions: write-all") == []


def test_detects_pull_request_target_checkout_edge_case():
    content = "on:\n  pull_request_target:\nsteps:\n  - uses: actions/checkout@v4"
    assert check_github_actions(PATH, content)
