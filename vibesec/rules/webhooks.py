import re

RULE_NAME = "Missing Webhook Verification"
SEVERITY = "MEDIUM"

PATTERNS = [
    (r'stripe\.webhooks(?!.*constructEvent)',
     "Stripe webhook used without constructEvent signature verification"),
    (r'req\.body.*stripe(?!.*stripe-signature)',
     "Stripe webhook body read without signature header check"),
    (r'x-github-event(?!.*x-hub-signature)',
     "GitHub webhook received without hub signature verification"),
    (r'webhook.*payload(?!.*secret)',
     "Webhook payload processed without secret verification"),
]

# Positive indicators that webhook IS being verified
SAFE_INDICATORS = [
    "constructEvent",
    "stripe-signature",
    "x-hub-signature",
    "webhook_secret",
    "WEBHOOK_SECRET",
    "verifySignature",
    "crypto.timingSafeEqual",
    "hmac",
    "abstractmethod",
    "raise NotImplementedError",
    "pass",
    "@abstract",
]

SKIP_FILES = {"README.md", "readme.md"}


def check_webhooks(file_path, content):
    findings = []

    filename = file_path.split("/")[-1].split("\\")[-1]
    if filename in SKIP_FILES:
        return findings

    ext = file_path.split(".")[-1].lower()
    if ext not in {"py", "js", "ts", "jsx", "tsx"}:
        return findings

    # Only scan files that mention webhooks
    if "webhook" not in content.lower() and "stripe" not in content.lower():
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue

        for pattern, description in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Check surrounding context for safe indicators
                start = max(0, line_num - 10)
                end = min(len(lines), line_num + 10)
                surrounding = "\n".join(lines[start:end])

                is_safe = any(
                    indicator in surrounding
                    for indicator in SAFE_INDICATORS
                )

                is_stub = False
                for idx, context_line in enumerate(surrounding.splitlines()):
                    context_stripped = context_line.strip()
                    if context_stripped.startswith("def ") or context_stripped.startswith("async def "):
                        for body_line in surrounding.splitlines()[idx + 1:]:
                            body_stripped = body_line.strip()
                            if not body_stripped or body_stripped.startswith("#"):
                                continue
                            if body_stripped in {
                                "pass",
                                "raise NotImplementedError",
                                "raise NotImplementedError()",
                            }:
                                is_stub = True
                            break
                        if is_stub:
                            break

                is_abstract = any(phrase in surrounding for phrase in [
                    "abstractmethod",
                    "raise NotImplementedError",
                    "@abc.abstractmethod",
                    "ABC",
                ])

                if not is_safe and not is_abstract and not is_stub:
                    findings.append({
                        "rule": RULE_NAME,
                        "severity": SEVERITY,
                        "file": file_path,
                        "line": line_num,
                        "message": description,
                        "fix_hint": "Verify webhook signatures using the provider's SDK. For Stripe use stripe.webhooks.constructEvent().",
                        "code_snippet": line.strip()[:80],
                    })
                break

    return findings