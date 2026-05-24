from vibesec.rules.secrets import check_secrets
from vibesec.rules.rls import check_rls
from vibesec.rules.auth_routes import check_auth_routes
from vibesec.rules.packages import check_packages
from vibesec.rules.sourcemaps import check_sourcemaps

ALL_RULES = [
	check_secrets,
	check_rls,
	check_auth_routes,
	check_packages,
	check_sourcemaps,
]
