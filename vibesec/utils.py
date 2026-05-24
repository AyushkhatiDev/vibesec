import os

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".yaml", ".yml", ".env", ".sql"
}

def walk_files(path):
    """Recursively yield all supported files in a directory."""
    if os.path.isfile(path):
        yield path
        return
    
    for root, dirs, files in os.walk(path):
        # Skip common non-code directories
        dirs[:] = [d for d in dirs if d not in {
            "node_modules", ".git", "venv", "__pycache__",
            ".next", "dist", "build", ".venv"
        }]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                yield os.path.join(root, file)

def read_file(path):
    """Read file content safely."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""