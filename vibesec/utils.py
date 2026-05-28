import os
import re
import shutil
import tempfile
import subprocess
from functools import lru_cache
from urllib.parse import urlparse

import requests


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
    "tests",
    "test-app",
}

DEFAULT_IGNORE = SKIP_DIRS

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_GITHUB_REPO_SIZE_KB = 500 * 1024

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

SUPPORTED_FILENAMES = {
    "Dockerfile",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}

TEXT_MAGIC_PREFIXES = (
    b"#!",
    b"import ",
    b"from ",
    b"const ",
    b"let ",
    b"var ",
    b"function ",
    b"{",
    b"[",
    b"---",
)


def _effective_max_file_size(max_file_size=None):
    return MAX_FILE_SIZE if max_file_size is None else int(max_file_size)


def _is_supported_file(file_name):
    if file_name in SUPPORTED_FILENAMES or file_name.lower() in SUPPORTED_FILENAMES:
        return True
    ext = os.path.splitext(file_name)[1].lower()
    return ext in SUPPORTED_EXTENSIONS


def is_binary_file(file_path):
    """Detect binary files using magic bytes and null bytes."""
    try:
        with open(file_path, "rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return True
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    if chunk.startswith(TEXT_MAGIC_PREFIXES):
        return False
    try:
        chunk.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def _matches_exclude(path, root, exclude_paths):
    if not exclude_paths:
        return False
    rel = os.path.relpath(path, root).replace("\\", "/")
    for pattern in exclude_paths:
        normalized = str(pattern).strip().strip("/").replace("\\", "/")
        if not normalized:
            continue
        if rel == normalized or rel.startswith(normalized + "/"):
            return True
    return False


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


@lru_cache(maxsize=64)
def _walk_files_cached(path, exclude_paths=(), max_file_size=None):
    if not path:
        return tuple()
    max_size = _effective_max_file_size(max_file_size)
    if os.path.isfile(path):
        try:
            if (
                not os.path.islink(path)
                and os.path.getsize(path) <= max_size
                and _is_supported_file(os.path.basename(path))
                and not is_binary_file(path)
            ):
                return (path,)
        except OSError:
            return tuple()
        return tuple()

    real_root = os.path.realpath(path)
    found = []
    ignore_patterns = tuple(load_ignore_patterns(path))

    for root, dirs, files in os.walk(path):
        dirs[:] = [
            d for d in dirs
            if d not in DEFAULT_IGNORE
            and not _matches_exclude(os.path.join(root, d), path, exclude_paths)
        ]

        rel_root = os.path.relpath(root, path)
        skip = False
        for pattern in ignore_patterns:
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

            try:
                if os.path.getsize(real_path) > max_size:
                    continue
            except OSError:
                continue

            if _matches_exclude(full_path, path, exclude_paths):
                continue

            if _is_supported_file(file) and not is_binary_file(real_path):
                found.append(full_path)

    return tuple(found)


def walk_files(path, exclude_paths=None, max_file_size=None):
    exclude_key = tuple(sorted(exclude_paths or ()))
    yield from _walk_files_cached(os.path.abspath(path), exclude_key, max_file_size)


def read_file(file_path):
    """Read a file as UTF-8 text; return empty string for unreadable/binary."""
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            return ""
        if is_binary_file(file_path):
            return ""
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


def _parse_github_repo(url):
    """Return (owner, repo, clone_url) for a validated GitHub repository URL."""
    if not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url.rstrip("/"))
    if parsed.netloc.lower() != "github.com":
        raise ValueError("Only github.com repository URLs are supported")

    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]

    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path):
        raise ValueError("Invalid GitHub URL format. Expected https://github.com/owner/repo")

    owner, repo = path.split("/", 1)
    return owner, repo, f"https://github.com/{owner}/{repo}"


def _check_github_repo_size(owner, repo):
    """Reject GitHub repositories larger than the configured size limit."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    response = requests.get(api_url, timeout=10)
    if response.status_code != 200:
        raise Exception(f"GitHub repository lookup failed: {response.status_code}")

    size_kb = response.json().get("size")
    if size_kb is None:
        raise Exception("GitHub repository size unavailable")
    if size_kb > MAX_GITHUB_REPO_SIZE_KB:
        raise Exception("Repository is larger than 500MB and cannot be scanned")


def clone_github_repo(url):
    """Clone a public GitHub repo to a temp directory and return the path."""
    owner, repo, clone_url = _parse_github_repo(url)
    _check_github_repo_size(owner, repo)

    tmp_dir = tempfile.mkdtemp(prefix="vibesec_")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", clone_url, tmp_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise Exception(f"Clone failed: {result.stderr}")
        return tmp_dir
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise Exception("Repository clone timed out after 60 seconds")
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
