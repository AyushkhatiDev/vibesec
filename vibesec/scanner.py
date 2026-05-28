import logging
from vibesec.utils import walk_files, read_file
from vibesec.rules import ALL_RULES

logger = logging.getLogger(__name__)


class Scanner:

    def __init__(self, path, display_path=None):
        self.path = path
        self.display_path = display_path

    def run(self):
        findings = []
        files = list(walk_files(self.path))

        for file_path in files:
            content = read_file(file_path)
            if not content:
                continue
            for rule in ALL_RULES:
                try:
                    results = rule(file_path, content)
                    findings.extend(results)
                except Exception as e:
                    logger.warning(f"Rule {rule.__name__} failed on {file_path}: {e}")

        # Clean up temp paths for GitHub URL scans
        if self.display_path and self.display_path != self.path:
            for finding in findings:
                finding["file"] = finding["file"].replace(self.path, self.display_path)

        return findings
