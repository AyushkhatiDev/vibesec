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
from vibesec.rules.flask_secrets import check_flask_secrets
from vibesec.rules.env_secrets import check_env_secrets
from vibesec.rules.sql_injection import check_sql_injection
from vibesec.rules.command_injection import check_command_injection
from vibesec.rules.path_traversal import check_path_traversal
from vibesec.rules.ssrf import check_ssrf
from vibesec.rules.insecure_deserialization import check_insecure_deserialization
from vibesec.rules.ssti import check_ssti
from vibesec.rules.weak_crypto import check_weak_crypto
from vibesec.rules.open_redirect import check_open_redirect
from vibesec.rules.nodejs_security import check_nodejs_security
from vibesec.rules.nextjs_security import check_nextjs_security
from vibesec.rules.docker_security import check_docker_security
from vibesec.rules.github_actions import check_github_actions

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
	check_flask_secrets,
	check_env_secrets,
	check_sql_injection,
	check_command_injection,
	check_path_traversal,
	check_ssrf,
	check_insecure_deserialization,
	check_ssti,
	check_weak_crypto,
	check_open_redirect,
	check_nodejs_security,
	check_nextjs_security,
	check_docker_security,
	check_github_actions,
]
