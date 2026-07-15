"""
Rule-specific fix templates for VibeSec's suggest_fix() MCP tool.

Each template encodes:
- How AI coding tools typically introduce this specific vulnerability
- The canonical fix pattern (not just advice — the actual transformation)
- Known pitfalls in the fix itself (so the LLM doesn't "fix" it wrong)
- A diff instruction that guides the LLM toward a real, applicable patch

This is the moat. Any agent can call an LLM with "fix this SQL injection."
These templates encode domain knowledge the host agent doesn't have:
how Cursor/Claude Code specifically introduce each bug pattern, and
exactly how to fix it without introducing a different bug.
"""

FIX_TEMPLATES = {
    # ─── Core AI-Code Rules ──────────────────────────────────────────
    "Hardcoded Secret": {
        "ai_pattern": (
            "AI tools copy credentials from tutorials, docs, and examples "
            "directly into source files. They treat API keys as configuration "
            "constants rather than secret material."
        ),
        "canonical_fix": (
            "Replace the literal value with an environment variable lookup. "
            "For Python: os.environ['KEY'] or os.getenv('KEY'). "
            "For JS/TS: process.env.KEY. "
            "Add the variable name to .env.example with a placeholder value."
        ),
        "diff_instruction": (
            "1. Replace the hardcoded string with os.environ.get('VAR_NAME') or process.env.VAR_NAME\n"
            "2. Add 'import os' if not already present (Python only)\n"
            "3. Use the original variable name uppercased as the env var name\n"
            "4. Keep the rest of the line/statement identical"
        ),
        "pitfalls": (
            "Don't move the secret to a config.py constant — that's still hardcoded. "
            "Don't use a default value that contains the actual secret. "
            "Don't use os.getenv('KEY', 'the-actual-secret-as-default')."
        ),
        "confidence": "high",
    },

    "Supabase RLS Disabled": {
        "ai_pattern": (
            "AI tools generate SQL migrations with ALTER TABLE ... DISABLE ROW LEVEL SECURITY "
            "because it's the simplest way to 'make queries work' during scaffolding."
        ),
        "canonical_fix": (
            "Enable RLS and create appropriate policies. "
            "ALTER TABLE table_name ENABLE ROW LEVEL SECURITY; "
            "CREATE POLICY ... ON table_name FOR SELECT USING (auth.uid() = user_id);"
        ),
        "diff_instruction": (
            "1. Replace DISABLE ROW LEVEL SECURITY with ENABLE ROW LEVEL SECURITY\n"
            "2. Add a basic SELECT policy using auth.uid() if a user_id column exists\n"
            "3. Add a comment noting that policies should be reviewed for the specific use case"
        ),
        "pitfalls": (
            "Don't just enable RLS without adding any policy — that locks everyone out. "
            "Always add at least a basic authenticated-user policy."
        ),
        "confidence": "high",
    },

    "SQL Injection Risk": {
        "ai_pattern": (
            "AI tools generate f-string and concatenation-based SQL because it looks "
            "simpler and more readable than parameterized queries. They treat SQL like "
            "any other string template."
        ),
        "canonical_fix": (
            "Use parameterized queries. "
            "Python: cursor.execute('SELECT * FROM t WHERE id = %s', (value,)). "
            "SQLAlchemy: text('SELECT * FROM t WHERE id = :id').bindparams(id=value). "
            "Never use f-strings, .format(), or + concatenation in SQL strings."
        ),
        "diff_instruction": (
            "1. Rewrite the SQL string to use %s (psycopg2), ? (sqlite3), or :name (SQLAlchemy) placeholders\n"
            "2. Move interpolated variables into a params tuple or dict as the second argument\n"
            "3. Remove f-string prefix, .format() calls, or + concatenation from the query string\n"
            "4. Keep the query logic identical — only change how variables are injected"
        ),
        "pitfalls": (
            "Don't use .format() as a 'fix' — it's equally injectable. "
            "Don't put the table/column name in a parameter — only values can be parameterized. "
            "If the table name is dynamic, whitelist it explicitly."
        ),
        "confidence": "high",
    },

    "Missing Route Authentication": {
        "ai_pattern": (
            "AI tools scaffold admin routes and API endpoints without auth middleware "
            "because they focus on getting the handler logic working first."
        ),
        "canonical_fix": (
            "Add authentication middleware/decorator to the route. "
            "Flask: @login_required. Express: auth middleware. "
            "Django: @login_required or LoginRequiredMixin."
        ),
        "diff_instruction": (
            "1. Add the appropriate auth decorator/middleware before the route handler\n"
            "2. Import the auth decorator if not already imported\n"
            "3. Keep the route handler logic unchanged"
        ),
        "pitfalls": (
            "Don't add auth to health check or public endpoints. "
            "Make sure the auth decorator is applied in the right order "
            "(before route-specific decorators)."
        ),
        "confidence": "medium",
    },

    "Hallucinated Package": {
        "ai_pattern": (
            "AI models fabricate package names that don't exist in the npm registry, "
            "creating a dependency confusion / typosquatting attack surface."
        ),
        "canonical_fix": (
            "Verify the package exists on npmjs.com. Replace with the correct, "
            "well-known package name, or implement the functionality directly."
        ),
        "diff_instruction": (
            "1. Remove or replace the hallucinated package name with the correct real package\n"
            "2. If no real equivalent exists, add a comment noting the dependency should be reviewed\n"
            "3. Update any import/require statements that reference the package"
        ),
        "pitfalls": (
            "Don't assume a similarly-named package is the right one — verify on npmjs.com. "
            "The hallucinated name might have been typosquatted by an attacker."
        ),
        "confidence": "medium",
    },

    "Source Map Exposure": {
        "ai_pattern": (
            "AI tools leave source map generation enabled in production builds "
            "and commit .map files because dev is the only environment they know."
        ),
        "canonical_fix": (
            "Disable source maps in production builds. "
            "Add *.map to .gitignore. Remove committed .map files. "
            "Set devtool: false or 'hidden-source-map' in webpack config."
        ),
        "diff_instruction": (
            "1. Set source map generation to false/hidden for production\n"
            "2. If this is a committed .map file, note it should be deleted and .gitignore updated"
        ),
        "pitfalls": (
            "Don't disable source maps in development — only production. "
            "hidden-source-map still generates maps but doesn't reference them in bundles."
        ),
        "confidence": "high",
    },

    "Unsafe JWT Handling": {
        "ai_pattern": (
            "AI tools set algorithm to 'none', disable verification, or store "
            "JWTs in localStorage because that's what many tutorials show."
        ),
        "canonical_fix": (
            "Always specify algorithms=['HS256'] or ['RS256'] explicitly. "
            "Never disable verification. Store tokens in httpOnly cookies, not localStorage."
        ),
        "diff_instruction": (
            "1. Add explicit algorithms parameter to jwt.decode()\n"
            "2. Remove verify=False or options={'verify_signature': False}\n"
            "3. If storing in localStorage, move to httpOnly cookie"
        ),
        "pitfalls": (
            "Don't allow algorithm negotiation from the token itself. "
            "Always pin the algorithm on the server side."
        ),
        "confidence": "high",
    },

    "Client-Side Role Trust": {
        "ai_pattern": (
            "AI tools implement admin checks using localStorage.getItem('role') === 'admin' "
            "or URL query parameters because client-side checks are simpler to scaffold."
        ),
        "canonical_fix": (
            "Move role checks to the server. Verify roles from the JWT/session on the backend. "
            "Client-side role checks are only for UI rendering, never for authorization."
        ),
        "diff_instruction": (
            "1. Add a comment noting this is UI-only and server must enforce authorization\n"
            "2. If this is an API call guard, move the check to the backend route\n"
            "3. Keep the client-side check for conditional rendering only"
        ),
        "pitfalls": (
            "Client-side role checks for UI rendering are fine and expected. "
            "The issue is when they're the ONLY authorization check."
        ),
        "confidence": "medium",
    },

    "Insecure Flask Configuration": {
        "ai_pattern": (
            "AI tools set DEBUG=True and hardcode SECRET_KEY because that's how "
            "Flask tutorials start. They never switch to production config."
        ),
        "canonical_fix": (
            "Set DEBUG from environment variable (default False). "
            "Generate SECRET_KEY with secrets.token_hex(32) or load from env. "
            "Never use a string literal as SECRET_KEY in production."
        ),
        "diff_instruction": (
            "1. Replace DEBUG=True with os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'\n"
            "2. Replace hardcoded SECRET_KEY with os.environ.get('SECRET_KEY') or secrets.token_hex(32)\n"
            "3. Add 'import os' and 'import secrets' if needed"
        ),
        "pitfalls": (
            "Don't use a 'fallback' secret key that's still a hardcoded string. "
            "secrets.token_hex() generates a new key each restart — use env var for persistence."
        ),
        "confidence": "high",
    },

    "Credentials in Environment File": {
        "ai_pattern": (
            "AI tools generate .env files with real-looking credentials "
            "and don't add .env to .gitignore."
        ),
        "canonical_fix": (
            "Replace real credentials with placeholders. "
            "Rename to .env.example. Add .env to .gitignore."
        ),
        "diff_instruction": (
            "1. Replace credential values with placeholder text like 'your-key-here'\n"
            "2. Add a comment noting this is an example file"
        ),
        "pitfalls": (
            "If the .env file was already committed, the secret is in git history. "
            "Rotate the credential immediately."
        ),
        "confidence": "high",
    },

    "Unsafe HTML Injection (XSS)": {
        "ai_pattern": (
            "AI tools use dangerouslySetInnerHTML, innerHTML, or document.write "
            "to render dynamic content because it's the simplest approach."
        ),
        "canonical_fix": (
            "Use safe rendering: React JSX text nodes, textContent instead of innerHTML, "
            "or DOMPurify.sanitize() if HTML rendering is truly needed."
        ),
        "diff_instruction": (
            "1. Replace innerHTML with textContent if HTML rendering isn't needed\n"
            "2. If HTML is needed, wrap input with DOMPurify.sanitize()\n"
            "3. For React, remove dangerouslySetInnerHTML and use JSX text interpolation"
        ),
        "pitfalls": (
            "Don't just escape & < > — use a proper sanitizer like DOMPurify. "
            "Custom escape functions almost always miss edge cases."
        ),
        "confidence": "high",
    },

    "Missing Webhook Verification": {
        "ai_pattern": (
            "AI tools scaffold webhook handlers that process the payload directly "
            "without verifying the signature, because that's extra code."
        ),
        "canonical_fix": (
            "Verify webhook signatures before processing. "
            "Stripe: stripe.Webhook.construct_event(payload, sig_header, webhook_secret). "
            "GitHub: compare HMAC-SHA256 of payload against X-Hub-Signature-256."
        ),
        "diff_instruction": (
            "1. Add signature verification at the top of the webhook handler\n"
            "2. Return 400 if verification fails\n"
            "3. Import the appropriate verification function\n"
            "4. Read the signing secret from an environment variable"
        ),
        "pitfalls": (
            "Don't use a timing-vulnerable string comparison for signatures. "
            "Use hmac.compare_digest() or the SDK's built-in verification."
        ),
        "confidence": "high",
    },

    "Permissive CORS Configuration": {
        "ai_pattern": (
            "AI tools set Access-Control-Allow-Origin: * with credentials "
            "because it 'just works' for cross-origin requests during development."
        ),
        "canonical_fix": (
            "Set specific allowed origins instead of wildcard. "
            "Never combine * with credentials: true. "
            "Use a whitelist: origins=['https://myapp.com']."
        ),
        "diff_instruction": (
            "1. Replace '*' with specific origin(s)\n"
            "2. If credentials are enabled, ensure origin is not '*'\n"
            "3. Use an environment variable for allowed origins"
        ),
        "pitfalls": (
            "Don't reflect the Origin header as-is — that's equivalent to wildcard. "
            "Whitelist specific origins."
        ),
        "confidence": "high",
    },

    # ─── Deeper Application Security Rules ────────────────────────────

    "Command Injection": {
        "ai_pattern": (
            "AI tools use os.system() and shell=True because subprocess.run([...]) "
            "is more verbose. They treat shell commands like string templates."
        ),
        "canonical_fix": (
            "Use subprocess.run() with an argument list and shell=False. "
            "For Node.js, use execFile/spawn instead of exec. "
            "Never pass user input to shell commands."
        ),
        "diff_instruction": (
            "1. Replace os.system(cmd) with subprocess.run(cmd_list, shell=False)\n"
            "2. Split the command string into a list of arguments\n"
            "3. Replace eval/exec with a safe alternative specific to the use case\n"
            "4. For subprocess calls, remove shell=True and use argument lists"
        ),
        "pitfalls": (
            "Don't just wrap user input in shlex.quote() — use argument lists. "
            "shlex.quote() has edge cases on Windows. "
            "subprocess.run(['ls', user_input]) is safe; subprocess.run(f'ls {user_input}', shell=True) is not."
        ),
        "confidence": "high",
    },

    "Path Traversal": {
        "ai_pattern": (
            "AI tools pass request parameters directly to open(), send_file(), "
            "or fs.readFile() without path validation."
        ),
        "canonical_fix": (
            "Canonicalize paths with os.path.realpath() and verify they start with "
            "the allowed base directory. Use werkzeug.utils.secure_filename() for uploads. "
            "Reject paths containing '..' segments."
        ),
        "diff_instruction": (
            "1. Add path canonicalization: resolved = os.path.realpath(os.path.join(base_dir, user_path))\n"
            "2. Add containment check: if not resolved.startswith(os.path.realpath(base_dir)): abort(403)\n"
            "3. Use the resolved path for the file operation\n"
            "4. Import os if not already imported"
        ),
        "pitfalls": (
            "Don't just strip '..' — canonicalize first, then check containment. "
            "Path.resolve() can follow symlinks outside the base directory."
        ),
        "confidence": "high",
    },

    "Server-Side Request Forgery": {
        "ai_pattern": (
            "AI tools pass user-provided URLs directly to requests.get(), fetch(), "
            "or axios without validating the destination."
        ),
        "canonical_fix": (
            "Validate URLs against an allowlist of domains/schemes. "
            "Block internal/private IP ranges (127.0.0.1, 10.x, 169.254.x, etc.). "
            "Use urlparse to check scheme and netloc before making the request."
        ),
        "diff_instruction": (
            "1. Parse the URL with urllib.parse.urlparse()\n"
            "2. Validate scheme is http or https\n"
            "3. Resolve hostname and check it's not a private IP\n"
            "4. Optionally check against an allowed domain list\n"
            "5. Add the validation before the request call"
        ),
        "pitfalls": (
            "Don't just check for 'localhost' — check all private IP ranges. "
            "DNS rebinding can bypass hostname checks. "
            "Resolve the hostname and check the IP, not just the hostname string."
        ),
        "confidence": "medium",
    },

    "Insecure Deserialization": {
        "ai_pattern": (
            "AI tools use pickle.loads(), yaml.load() without SafeLoader, or "
            "marshal.loads() because they're the first search results for serialization."
        ),
        "canonical_fix": (
            "Use safe alternatives: json.loads() for data, yaml.safe_load() for YAML, "
            "never unpickle untrusted data. If pickle is required, use hmac to "
            "verify integrity before deserializing."
        ),
        "diff_instruction": (
            "1. Replace yaml.load(data) with yaml.safe_load(data)\n"
            "2. Replace pickle.loads(untrusted) with json.loads() if possible\n"
            "3. If pickle is required, add HMAC verification before deserializing\n"
            "4. Replace Loader=yaml.Loader with Loader=yaml.SafeLoader"
        ),
        "pitfalls": (
            "yaml.load() without Loader= defaults to unsafe in older PyYAML versions. "
            "Always specify Loader=yaml.SafeLoader explicitly."
        ),
        "confidence": "high",
    },

    "Server-Side Template Injection": {
        "ai_pattern": (
            "AI tools use render_template_string(user_input) or construct "
            "Jinja2 templates from user data because it's more 'dynamic.'"
        ),
        "canonical_fix": (
            "Use render_template() with a file-based template and pass user data "
            "as template variables, not as part of the template string itself."
        ),
        "diff_instruction": (
            "1. Replace render_template_string(user_data) with render_template('template.html', data=user_data)\n"
            "2. Create a template file if needed\n"
            "3. Pass user input as template context variables, not template source"
        ),
        "pitfalls": (
            "Jinja2 autoescaping only prevents XSS, not SSTI. "
            "The issue is user data IN the template, not rendered BY the template."
        ),
        "confidence": "high",
    },

    "Weak Cryptography": {
        "ai_pattern": (
            "AI tools use MD5/SHA1 for password hashing, random.random() for tokens, "
            "and DES/RC4 for encryption because they appear in older tutorials."
        ),
        "canonical_fix": (
            "Use bcrypt/argon2 for passwords, secrets.token_hex() for tokens, "
            "and AES-256-GCM for encryption. SHA-256+ for integrity hashing."
        ),
        "diff_instruction": (
            "1. Replace hashlib.md5/sha1 with hashlib.sha256 for integrity checks\n"
            "2. Replace random.random()/randint() for tokens with secrets.token_hex()\n"
            "3. For passwords, replace hash functions with bcrypt.hashpw()\n"
            "4. Import the appropriate module (secrets, bcrypt)"
        ),
        "pitfalls": (
            "SHA-256 is fine for integrity checks but NOT for password storage. "
            "Passwords need bcrypt/argon2 with salt, not any hash function."
        ),
        "confidence": "high",
    },

    "Open Redirect": {
        "ai_pattern": (
            "AI tools use redirect(request.args.get('next')) without validating "
            "the destination URL, enabling phishing attacks."
        ),
        "canonical_fix": (
            "Validate redirect URLs are relative (start with /) or match an allowed domain list. "
            "Use url_has_allowed_host_and_scheme() in Django or manual urlparse checks."
        ),
        "diff_instruction": (
            "1. Parse the redirect URL and verify it's relative or on an allowed domain\n"
            "2. Reject URLs with different schemes (javascript:, data:, etc.)\n"
            "3. Fall back to a safe default URL if validation fails\n"
            "4. Add the validation before the redirect call"
        ),
        "pitfalls": (
            "Don't just check startswith('/') — //evil.com also starts with //. "
            "Use urlparse and verify netloc is empty or matches your domain."
        ),
        "confidence": "high",
    },

    # ─── Platform and Supply Chain Rules ──────────────────────────────

    "Node.js Security Misconfiguration": {
        "ai_pattern": (
            "AI tools scaffold Express apps without helmet, with insecure cookie settings, "
            "and without rate limiting because the minimal example works without them."
        ),
        "canonical_fix": (
            "Add helmet() middleware, set secure cookie options "
            "(httpOnly, secure, sameSite), and add rate limiting."
        ),
        "diff_instruction": (
            "1. Add app.use(helmet()) near the top of middleware chain\n"
            "2. Set cookie options: httpOnly: true, secure: true, sameSite: 'strict'\n"
            "3. Add rate limiting middleware if missing\n"
            "4. Add the appropriate imports/requires"
        ),
        "pitfalls": (
            "Don't set secure: true in development — cookies won't work without HTTPS. "
            "Use an environment check: secure: process.env.NODE_ENV === 'production'."
        ),
        "confidence": "medium",
    },

    "Next.js Security Issue": {
        "ai_pattern": (
            "AI tools create API routes without auth checks, expose secrets via "
            "NEXT_PUBLIC_ prefix, and skip security headers in next.config.js."
        ),
        "canonical_fix": (
            "Add auth checks to API routes. Move secrets from NEXT_PUBLIC_ to server-only env vars. "
            "Add security headers in next.config.js."
        ),
        "diff_instruction": (
            "1. Add session/auth check at the top of API route handlers\n"
            "2. Rename NEXT_PUBLIC_SECRET_* to SECRET_* (server-only)\n"
            "3. Update references to use server-side env access\n"
            "4. Add security headers configuration"
        ),
        "pitfalls": (
            "NEXT_PUBLIC_ vars are embedded in the client bundle at build time. "
            "Removing the prefix after deployment doesn't help — rebuild required."
        ),
        "confidence": "medium",
    },

    "Docker Security Issue": {
        "ai_pattern": (
            "AI tools generate Dockerfiles running as root, with secrets in ENV/ARG, "
            "using :latest tags, and curl-pipe-bash install patterns."
        ),
        "canonical_fix": (
            "Add USER nonroot, use build secrets or multi-stage builds for credentials, "
            "pin image tags to specific versions, avoid curl|bash."
        ),
        "diff_instruction": (
            "1. Add 'RUN adduser -D appuser' and 'USER appuser' before CMD\n"
            "2. Replace ENV/ARG secrets with --mount=type=secret\n"
            "3. Replace :latest with a specific version tag\n"
            "4. Replace 'curl | bash' with explicit download-and-verify steps"
        ),
        "pitfalls": (
            "USER directive only affects subsequent instructions. "
            "Place it after all RUN commands that need root."
        ),
        "confidence": "medium",
    },

    "GitHub Actions Security Issue": {
        "ai_pattern": (
            "AI tools generate workflows with unpinned actions (@main/@master), "
            "pull_request_target with checkout, and shell injection via ${{ }}."
        ),
        "canonical_fix": (
            "Pin actions to full SHA commits. Use pull_request instead of pull_request_target. "
            "Pass untrusted input through environment variables, not direct interpolation."
        ),
        "diff_instruction": (
            "1. Replace @v4 or @main with @<full-sha> (pin to commit hash)\n"
            "2. Replace ${{ github.event.pull_request.title }} with env var: env: TITLE: ${{ ... }}\n"
            "3. Replace pull_request_target with pull_request where possible\n"
            "4. Add permissions: with least-privilege scope"
        ),
        "pitfalls": (
            "Pinning to @v4 is better than @main but still mutable. "
            "Full SHA is the only truly immutable reference."
        ),
        "confidence": "medium",
    },
}


def get_template(rule_name):
    """Look up the fix template for a rule.

    Returns the template dict if found, or a generic fallback.
    """
    if rule_name in FIX_TEMPLATES:
        return FIX_TEMPLATES[rule_name]

    # Fuzzy match — handle minor name variations
    rule_lower = rule_name.lower()
    for key, template in FIX_TEMPLATES.items():
        if key.lower() in rule_lower or rule_lower in key.lower():
            return template

    # Generic fallback
    return {
        "ai_pattern": "AI coding tools may introduce this vulnerability during scaffolding.",
        "canonical_fix": "Review and fix according to the fix_hint provided.",
        "diff_instruction": "Apply the fix described in the fix_hint to the affected code.",
        "pitfalls": "Verify the fix doesn't introduce a different vulnerability.",
        "confidence": "low",
    }
