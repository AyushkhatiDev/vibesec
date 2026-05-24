from vibesec.rules.secrets import check_secrets
from vibesec.rules.rls import check_rls
from vibesec.rules.auth_routes import check_auth_routes
from vibesec.rules.packages import check_packages
from vibesec.rules.sourcemaps import check_sourcemaps
from vibesec.rules.jwt import check_jwt
from vibesec.rules.xss import check_xss
from vibesec.rules.roles import check_roles
from vibesec.rules.webhooks import check_webhooks
from vibesec.rules.cors import check_cors

ALL_RULES = [
	check_secrets,
	check_rls,
	check_auth_routes,
	check_packages,
	check_sourcemaps,
	check_jwt,
	check_xss,
	check_roles,
	check_webhooks,
	check_cors,
]
