from vibesec.utils import walk_files, read_file
from vibesec.rules.secrets import check_secrets
from vibesec.rules.rls import check_rls
from vibesec.rules.auth_routes import check_auth_routes
from vibesec.rules.packages import check_packages
from vibesec.rules.sourcemaps import check_sourcemaps

class Scanner:

    def __init__(self, path):
        self.path = path
        self.rules = [
            check_secrets,
            check_rls,
            check_auth_routes,
            check_packages,
            check_sourcemaps,
        ]

    def run(self):
        findings = []
        files = list(walk_files(self.path))

        for file_path in files:
            content = read_file(file_path)
            if not content:
                continue
            for rule in self.rules:
                try:
                    results = rule(file_path, content)
                    findings.extend(results)
                except Exception:
                    pass

        return findings