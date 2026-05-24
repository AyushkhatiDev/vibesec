import pytest
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


#   SECRETS          

def test_secrets_detects_api_key():
    content = 'api_key = "FAKE_KEY_FOR_TESTING_ONLY_XXXXXXXXXXXXXXXXXXXXXXXXX"'
    findings = check_secrets("config.py", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"

def test_secrets_detects_supabase_key():
    content = 'SUPABASE_SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake"'
    findings = check_secrets("config.py", content)
    assert len(findings) == 1

def test_secrets_detects_stripe_key():
    content = 'stripe_secret = "FAKE_STRIPE_FOR_TESTING_ONLY"'
    findings = check_secrets("config.py", content)
    assert len(findings) == 1

def test_secrets_detects_database_url():
    content = 'DATABASE_URL = "postgresql://admin:password123@localhost/mydb"'
    findings = check_secrets("config.py", content)
    assert len(findings) == 1

def test_secrets_skips_comments():
    content = '# api_key = "FAKE_KEY_FOR_TESTING_ONLY_XXXXXXXXXXXXXXXXXXXXXXXXX"'
    findings = check_secrets("config.py", content)
    assert len(findings) == 0

def test_secrets_skips_example_files():
    content = 'api_key = "FAKE_KEY_FOR_TESTING_ONLY_XXXXXXXXXXXXXXXXXXXXXXXXX"'
    findings = check_secrets(".env.example", content)
    assert len(findings) == 0

def test_secrets_clean_code():
    content = 'api_key = os.environ.get("API_KEY")'
    findings = check_secrets("config.py", content)
    assert len(findings) == 0


#   RLS          

def test_rls_detects_disable():
    content = "ALTER TABLE users DISABLE ROW LEVEL SECURITY;"
    findings = check_rls("migration.sql", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"

def test_rls_detects_multiple_tables():
    content = """
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE posts DISABLE ROW LEVEL SECURITY;
"""
    findings = check_rls("migration.sql", content)
    assert len(findings) == 2

def test_rls_skips_comments():
    content = "-- ALTER TABLE users DISABLE ROW LEVEL SECURITY;"
    findings = check_rls("migration.sql", content)
    assert len(findings) == 0

def test_rls_clean_code():
    content = "ALTER TABLE users ENABLE ROW LEVEL SECURITY;"
    findings = check_rls("migration.sql", content)
    assert len(findings) == 0


#   AUTH ROUTES          

def test_auth_routes_detects_unprotected_admin():
    content = """
@app.route("/api/admin/users")
def get_users():
    return db.query("SELECT * FROM users")
"""
    findings = check_auth_routes("routes.py", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"

def test_auth_routes_safe_with_decorator():
    content = """
@login_required
@app.route("/api/admin/users")
def get_users():
    return db.query("SELECT * FROM users")
"""
    findings = check_auth_routes("routes.py", content)
    assert len(findings) == 0

def test_auth_routes_skips_non_code_files():
    content = '@app.route("/api/admin/users")'
    findings = check_auth_routes("README.md", content)
    assert len(findings) == 0


#   PACKAGES          

def test_packages_detects_hallucinated():
    content = '{"dependencies": {"react-auth-handler": "^1.0.0"}}'
    findings = check_packages("package.json", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"

def test_packages_detects_multiple_hallucinated():
    content = """{
        "dependencies": {
            "react-auth-handler": "^1.0.0",
            "supabase-helpers": "^2.0.0"
        }
    }"""
    findings = check_packages("package.json", content)
    assert len(findings) == 2

def test_packages_skips_non_package_json():
    content = '{"react-auth-handler": "^1.0.0"}'
    findings = check_packages("config.json", content)
    assert len(findings) == 0

def test_packages_clean_dependencies():
    content = """{
        "dependencies": {
            "react": "^18.0.0",
            "express": "^4.18.0"
        }
    }"""
    findings = check_packages("package.json", content)
    assert len(findings) == 0


#   SOURCE MAPS          

def test_sourcemaps_detects_enabled():
    content = "sourceMap: true"
    findings = check_sourcemaps("webpack.config.js", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"

def test_sourcemaps_detects_react_env():
    content = "GENERATE_SOURCEMAP=true"
    findings = check_sourcemaps(".env.production", content)
    assert len(findings) == 1

def test_sourcemaps_clean_config():
    content = "sourceMap: false"
    findings = check_sourcemaps("webpack.config.js", content)
    assert len(findings) == 0


#   JWT          

def test_jwt_detects_none_algorithm():
    content = 'const decoded = jwt.decode(token, { algorithms: ["none"] })'
    findings = check_jwt("auth.js", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"

def test_jwt_detects_localstorage():
    content = 'localStorage.setItem("token", jwtToken)'
    findings = check_jwt("auth.js", content)
    assert len(findings) == 1

def test_jwt_skips_comments():
    content = '// localStorage.setItem("token", jwtToken)'
    findings = check_jwt("auth.js", content)
    assert len(findings) == 0

def test_jwt_clean_code():
    content = 'const decoded = jwt.verify(token, process.env.JWT_SECRET)'
    findings = check_jwt("auth.js", content)
    assert len(findings) == 0


#   XSS          

def test_xss_detects_dangerous_html():
    content = 'return <div dangerouslySetInnerHTML={{ __html: userInput }} />'
    findings = check_xss("Component.jsx", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"

def test_xss_detects_eval():
    content = "eval(userInput)"
    findings = check_xss("script.js", content)
    assert len(findings) == 1

def test_xss_skips_python_files():
    content = 'dangerouslySetInnerHTML={{ __html: userInput }}'
    findings = check_xss("views.py", content)
    assert len(findings) == 0

def test_xss_clean_code():
    content = 'return <div>{sanitizedContent}</div>'
    findings = check_xss("Component.jsx", content)
    assert len(findings) == 0


#   ROLES          

def test_roles_detects_localstorage_role():
    content = 'const role = localStorage.getItem("role")'
    findings = check_roles("auth.js", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"

def test_roles_detects_admin_flag():
    content = 'const isAdmin = localStorage.getItem("admin")'
    findings = check_roles("auth.js", content)
    assert len(findings) == 1

def test_roles_clean_code():
    content = 'const role = await getUserRoleFromServer(userId)'
    findings = check_roles("auth.js", content)
    assert len(findings) == 0


#   WEBHOOKS          

def test_webhooks_detects_unverified_stripe():
    content = """
app.post('/webhook', (req, res) => {
    const event = req.body
    stripe.webhooks.processEvent(event)
})
"""
    findings = check_webhooks("webhook.js", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"

def test_webhooks_safe_with_verification():
    content = """
app.post('/webhook', (req, res) => {
    const sig = req.headers['stripe-signature']
    const event = stripe.webhooks.constructEvent(body, sig, secret)
})
"""
    findings = check_webhooks("webhook.js", content)
    assert len(findings) == 0

def test_webhooks_skips_files_without_webhook():
    content = "const x = 1 + 1"
    findings = check_webhooks("utils.js", content)
    assert len(findings) == 0


#   CORS          

def test_cors_detects_wildcard():
    content = "app.use(cors())"
    findings = check_cors("server.js", content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"

def test_cors_detects_wildcard_origin():
    content = 'origin: "*"'
    findings = check_cors("server.js", content)
    assert len(findings) == 1

def test_cors_safe_with_specific_origin():
    content = """
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS
}))
"""
    findings = check_cors("server.js", content)
    assert len(findings) == 0

def test_cors_skips_files_without_cors():
    content = "const x = 1 + 1"
    findings = check_cors("utils.js", content)
    assert len(findings) == 0
