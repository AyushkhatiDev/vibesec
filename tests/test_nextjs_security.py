from vibesec.rules.nextjs_security import check_nextjs_security


def test_detects_api_route_without_auth():
    content = "export default function handler(req, res) {\n  res.json({ ok: true })\n}"
    assert check_nextjs_security("pages/api/users.js", content)


def test_detects_public_secret_env():
    assert check_nextjs_security("app.js", "const x = process.env.NEXT_PUBLIC_SECRET_KEY")


def test_detects_missing_next_headers():
    assert check_nextjs_security("next.config.js", "module.exports = {}")


def test_allows_api_route_with_session():
    content = "export default function handler(req, res) {\n  const session = getServerSession(req, res)\n  res.json({ ok: true })\n}"
    assert check_nextjs_security("pages/api/users.js", content) == []


def test_allows_next_headers_config():
    assert check_nextjs_security("next.config.js", "module.exports = { async headers() { return [] } }") == []


def test_detects_server_action_without_validation_edge_case():
    assert check_nextjs_security("app/actions.js", '"use server"\nexport async function save(formData) { return true }')
