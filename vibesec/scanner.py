from vibesec.utils import walk_files, read_file
from vibesec.rules import ALL_RULES


class Scanner:

    def __init__(self, path):
        self.path = path

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
                except Exception:
                    pass

        return findings
