import os

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib


DEFAULT_CONFIG = {
    "ignore": [],
    "severity_threshold": None,
    "max_file_size": None,
    "exclude_paths": [],
    "exclude_rules": [],
    "rules": {},
}


def find_config(start_path):
    path = start_path
    if os.path.isfile(path):
        path = os.path.dirname(path)
    path = os.path.abspath(path)
    while True:
        candidate = os.path.join(path, "vibesec.toml")
        if os.path.exists(candidate):
            return candidate
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def load_config(scan_path):
    config = dict(DEFAULT_CONFIG)
    config_path = find_config(scan_path)
    if not config_path:
        return config

    try:
        with open(config_path, "rb") as handle:
            data = tomllib.load(handle)
    except Exception:
        return config

    vibesec_config = data.get("vibesec", {})
    config["ignore"] = list(vibesec_config.get("ignore", []))
    config["severity_threshold"] = vibesec_config.get("severity_threshold")
    config["max_file_size"] = vibesec_config.get("max_file_size")
    config["exclude_paths"] = list(vibesec_config.get("exclude_paths", []))
    config["exclude_rules"] = list(vibesec_config.get("exclude_rules", []))
    config["rules"] = vibesec_config.get("rules", {})
    return config


def merge_ignore(config, cli_ignore):
    values = list(config.get("ignore", [])) + list(config.get("exclude_rules", []))
    if cli_ignore:
        values.extend(part.strip() for part in cli_ignore.split(",") if part.strip())
    return [value.lower() for value in values if value]
