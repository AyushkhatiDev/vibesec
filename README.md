# 🔒 VibeSec

**Security scanner for AI-generated code.**

[![PyPI version](https://badge.fury.io/py/vibesec.svg)](https://badge.fury.io/py/vibesec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/AyushkhatiDev/vibesec?style=social)](https://github.com/AyushkhatiDev/vibesec)

45% of AI-generated code ships with critical vulnerabilities. Cursor, Claude Code, Bolt, and Lovable generate insecure patterns that existing tools miss. VibeSec catches them before you deploy.

```
$ vibesec scan ./my-cursor-app

  VibeSec v0.1.0 — AI-Generated Code Security Scanner

  ● CRITICAL    7 findings
  ● HIGH        2 findings

  CRITICAL — Hardcoded Secret
  File: src/lib/supabase.ts  Line: 12
  Found: SUPABASE_SERVICE_KEY hardcoded in source code
  Fix:   Move to environment variables. Never commit secrets to git.

  CRITICAL — Supabase RLS Disabled
  File: supabase/migrations/001_init.sql  Line: 34
  Found: ALTER TABLE users DISABLE ROW LEVEL SECURITY
  Fix:   Enable RLS + add user isolation policies.

  9 findings in ./my-cursor-app
```

---

## Why VibeSec

Existing tools like Semgrep, Snyk, and CodeQL are great — but they were built for human-written code. AI tools generate specific anti-patterns that these scanners miss:

| Pattern | Semgrep | Snyk | VibeSec |
|---|---|---|---|
| Hardcoded secrets | ✓ | ✓ | ✓ |
| Supabase RLS disabled | ✗ | ✗ | ✓ |
| Hallucinated npm packages | ✗ | ✗ | ✓ |
| Missing auth on scaffolded routes | Partial | ✗ | ✓ |
| Source map exposure in build config | ✗ | ✗ | ✓ |
| AI-specific JWT misuse | ✗ | ✗ | ✓ |

---

## Install

```bash
pip install vibesec
```

---

## Usage

**Scan a directory:**
```bash
vibesec scan ./my-project
```

**Scan and get AI-powered fix suggestions:**
```bash
vibesec scan ./my-project --fix
```

**Export results as JSON (for CI/CD):**
```bash
vibesec scan ./my-project --output json
```

**Filter by severity:**
```bash
vibesec scan ./my-project --severity critical
```

**Ignore specific checks:**
```bash
vibesec scan ./my-project --ignore rls,cors
```

---

## What VibeSec Checks

### 🔴 CRITICAL

**1. Hardcoded Secrets**
API keys, passwords, tokens, and database URLs hardcoded in source files. LLMs replicate tutorial patterns where secrets are hardcoded.

```python
# VibeSec catches this
api_key = "sk-abc123..."
SUPABASE_SERVICE_KEY = "eyJhbGci..."
stripe_secret = "sk_live_..."
```

**2. Supabase RLS Disabled**
Row Level Security disabled — any authenticated user can read or modify all data. LLMs skip RLS to make queries work quickly in scaffolding.

```sql
-- VibeSec catches this
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
```

### 🟡 HIGH

**3. Missing Route Authentication**
Admin and sensitive API routes scaffolded without authentication middleware. LLMs build the happy path without thinking about access control.

**4. Hallucinated Packages**
npm packages that don't exist — a typosquatting attack surface. LLMs generate plausible-sounding package names that aren't real.

```json
// VibeSec catches this
"react-auth-handler": "^1.0.0",
"supabase-helpers": "^2.1.0"
```

**5. Source Map Exposure**
Build config exposes full source code via `.map` files in production.

### 🟠 MEDIUM

**6. Unsafe JWT Handling** — JWT decoded without verification, or `none` algorithm accepted

**7. dangerouslySetInnerHTML** — Direct HTML injection without sanitization

**8. Client-Side Role Trust** — Admin checks done using `localStorage` values

**9. Missing Webhook Verification** — Stripe/GitHub webhooks without signature check

**10. Permissive CORS** — Wildcard CORS with credentials enabled

---

## GitHub Actions Integration

Add VibeSec to your CI/CD pipeline:

```yaml
# .github/workflows/vibesec.yml
name: VibeSec Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install VibeSec
        run: pip install vibesec
      - name: Run Security Scan
        run: vibesec scan . --output json --severity high
```

---

## Development

```bash
git clone https://github.com/AyushkhatiDev/vibesec
cd vibesec
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest tests/
```

---

## Contributing

VibeSec is open source and contributions are welcome.

**Adding a new rule:**
1. Create `vibesec/rules/your_rule.py`
2. Implement `check_your_rule(file_path, content) -> list[dict]`
3. Register it in `vibesec/rules/__init__.py`
4. Add test cases in `tests/corpus/`
5. Open a PR

Each finding must return:
```python
{
    "rule": "Rule Name",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "file": file_path,
    "line": line_number,
    "message": "What was found",
    "fix_hint": "How to fix it",
    "code_snippet": "offending line"
}
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guide.

---

## Roadmap

- [x] Secrets detection
- [x] Supabase RLS checker
- [x] Missing auth on routes
- [x] Hallucinated package detector
- [x] Source map exposure
- [ ] JWT misuse rules
- [ ] dangerouslySetInnerHTML
- [ ] Client-side role trust
- [ ] Webhook verification
- [ ] Permissive CORS
- [ ] GitHub Action marketplace listing
- [ ] Web app (paste URL → get report)
- [ ] SARIF output for GitHub Security tab
- [ ] VS Code extension

---

## Built By

[Ayush Khati](https://github.com/AyushkhatiDev) — BCA student building real tools for real problems.

Found a bug? [Open an issue](https://github.com/AyushkhatiDev/vibesec/issues).
Want a rule added? [Start a discussion](https://github.com/AyushkhatiDev/vibesec/discussions).

---

## License

MIT — free to use, modify, and distribute.

---

<p align="center">
  <sub>Built because 45% of vibe-coded apps ship with critical vulnerabilities. Someone had to fix that.</sub>
</p>