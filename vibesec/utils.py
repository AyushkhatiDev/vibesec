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

DEFAULT_IGNORE = SKIP_DIRS

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".sql",
}


def load_ignore_patterns(path):
    """Load patterns from .vibesecignore in the root directory."""
    if not path:
        return []
    if os.path.isfile(path):
        directory = os.path.dirname(path)
    else:
        directory = path
    ignore_file = os.path.join(directory, ".vibesecignore")
    if not os.path.exists(ignore_file):
        return []
    patterns = []
    try:
        with open(ignore_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except Exception:
        pass
    return patterns


def walk_files(path):
    if not path:
        return
    if os.path.isfile(path):
        if not os.path.islink(path):
            yield path
        return

    real_root = os.path.realpath(path)

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORE]

        rel_root = os.path.relpath(root, path)
        skip = False
        for pattern in load_ignore_patterns(path):
            if rel_root == pattern or rel_root.startswith(pattern):
                skip = True
                break
        if skip:
            dirs[:] = []
            continue

        for file in files:
            full_path = os.path.join(root, file)

            # Skip symlinks — prevents host file exfiltration
            if os.path.islink(full_path):
                continue

            # Path containment check
            real_path = os.path.realpath(full_path)
            if not real_path.startswith(real_root + os.sep):
                continue

            ext = os.path.splitext(file)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                yield full_path


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