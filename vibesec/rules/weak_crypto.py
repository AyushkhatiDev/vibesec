import re

from vibesec.rules.common import JS_EXTENSIONS, PY_EXTENSIONS, finding, is_comment, should_skip_file

RULE_NAME = "Weak Cryptography"
FIX_HASH = "Use SHA-256/SHA-512, BLAKE2, or a password hashing KDF where appropriate. MD5/SHA1 are weak."
FIX_RANDOM = "Use secrets.token_hex(), secrets.token_urlsafe(), or crypto.randomBytes() for security tokens."

PY_PATTERNS = [
    (r"\bhashlib\.md5\s*\(", "LOW", "hashlib.md5() is weak; may be acceptable only for non-security checksums", FIX_HASH),
    (r"\bhashlib\.sha1\s*\(", "HIGH", "hashlib.sha1() is weak for security-sensitive hashing", FIX_HASH),
    (r"(token|secret|password|key|session|csrf|nonce)[^#\n]*\brandom\.(random|randint)\s*\(", "MEDIUM", "random module used for security token generation", FIX_RANDOM),
    (r"\brandom\.(random|randint)\s*\([^#\n]*(token|secret|password|key|session|csrf|nonce)", "MEDIUM", "random module used for security token generation", FIX_RANDOM),
    (r"\b(DES|ARC4|RC4|RC2|TripleDES|3DES)\b", "HIGH", "Weak cipher usage detected", "Use modern AEAD ciphers such as AES-GCM or ChaCha20-Poly1305."),
]

JS_PATTERNS = [
    (r"\bcrypto\.createHash\s*\(\s*['\"]md5['\"]", "HIGH", "crypto.createHash('md5') is weak", FIX_HASH),
    (r"\bcrypto\.createHash\s*\(\s*['\"]sha1['\"]", "HIGH", "crypto.createHash('sha1') is weak", FIX_HASH),
    (r"(token|secret|password|key|session|csrf|nonce)[^#\n]*\bMath\.random\s*\(", "MEDIUM", "Math.random() used for security-sensitive value", FIX_RANDOM),
    (r"\bMath\.random\s*\([^#\n]*(token|secret|password|key|session|csrf|nonce)", "MEDIUM", "Math.random() used for security-sensitive value", FIX_RANDOM),
]


def _check_patterns(file_path, content, patterns):
    findings = []
    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if is_comment(stripped) or "secrets.token_hex" in line or "secrets.token_urlsafe" in line:
            continue
        for pattern, severity, message, fix in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(finding(RULE_NAME, severity, file_path, line_num, message, fix, line))
                break
    return findings


def check_weak_crypto(file_path, content):
    if should_skip_file(file_path, PY_EXTENSIONS | JS_EXTENSIONS):
        return []
    if file_path.endswith(".py"):
        return _check_patterns(file_path, content, PY_PATTERNS)
    return _check_patterns(file_path, content, JS_PATTERNS)
