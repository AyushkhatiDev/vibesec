import os
import tempfile
import subprocess


SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
}


def walk_files(path):
    """Yield file paths under the given path, skipping common dependency dirs."""
    if not path:
        return
    if os.path.isfile(path):
        yield path
        return
    if not os.path.isdir(path):
        return

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            yield os.path.join(root, filename)


def read_file(file_path):
    """Read a file as UTF-8 text; return empty string for unreadable/binary."""
    try:
        with open(file_path, "rb") as handle:
            data = handle.read()
    except OSError:
        return ""

    if b"\x00" in data:
        return ""

    try:
        return data.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return ""


def is_github_url(path):
    return path.startswith("https://github.com/") or path.startswith("github.com/")


def clone_github_repo(url):
    """Clone a public GitHub repo to a temp directory and return the path."""
    if not url.startswith("https://"):
        url = "https://" + url

    # Remove .git if present
    url = url.rstrip("/").replace(".git", "")

    tmp_dir = tempfile.mkdtemp(prefix="vibesec_")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", url, tmp_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise Exception(f"Clone failed: {result.stderr}")
        return tmp_dir
    except subprocess.TimeoutExpired:
        raise Exception("Repository clone timed out after 60 seconds")