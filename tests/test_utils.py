import os
import tempfile
import shutil
import pytest
from vibesec.utils import walk_files, load_ignore_patterns


@pytest.fixture
def temp_workspace():
    """Create a temporary workspace for testing walk_files and ignore logic."""
    temp_dir = tempfile.mkdtemp(prefix="vibesec_test_workspace_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_walk_files_finds_supported_files(temp_workspace):
    # Create test files with supported and unsupported extensions
    py_file = os.path.join(temp_workspace, "app.py")
    js_file = os.path.join(temp_workspace, "index.js")
    txt_file = os.path.join(temp_workspace, "notes.txt")

    with open(py_file, "w") as f:
        f.write("print('hello')")
    with open(js_file, "w") as f:
        f.write("console.log('hello')")
    with open(txt_file, "w") as f:
        f.write("some text")

    files = list(walk_files(temp_workspace))
    assert py_file in files
    assert js_file in files
    assert txt_file not in files  # .txt is not a supported extension


def test_walk_files_skips_symlinks(temp_workspace):
    # Create a real file
    real_file = os.path.join(temp_workspace, "target.py")
    with open(real_file, "w") as f:
        f.write("x = 1")

    # Create a symlink pointing to the real file
    link_file = os.path.join(temp_workspace, "link.py")
    try:
        os.symlink(real_file, link_file)
    except OSError:
        pytest.skip("Symlinks are not supported on this platform/privilege level")

    files = list(walk_files(temp_workspace))
    assert real_file in files
    assert link_file not in files  # Symlink must be skipped


def test_walk_files_obeys_vibesecignore(temp_workspace):
    # Create files
    app_py = os.path.join(temp_workspace, "app.py")
    ignored_dir = os.path.join(temp_workspace, "ignored_dir")
    os.makedirs(ignored_dir, exist_ok=True)
    ignored_py = os.path.join(ignored_dir, "secret.py")

    with open(app_py, "w") as f:
        f.write("import os")
    with open(ignored_py, "w") as f:
        f.write("secret = 'abc'")

    # Write .vibesecignore
    ignore_file = os.path.join(temp_workspace, ".vibesecignore")
    with open(ignore_file, "w") as f:
        f.write("# ignore list\nignored_dir\n")

    files = list(walk_files(temp_workspace))
    assert app_py in files
    assert ignored_py not in files  # Should be ignored because ignored_dir is in .vibesecignore
