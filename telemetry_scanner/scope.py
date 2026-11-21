"""HTTP URL normalization and scope checks shared by all network paths."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class ScopeError(ValueError):
    """Raised when a URL is malformed or outside the explicitly approved scope."""


def normalize_http_url(value: str) -> str:
    if not isinstance(value, str):
        raise ScopeError("Use an http(s) URL without embedded credentials.")
    value = value.strip()
    if not value or "\\" in value or any(ord(char) < 32 or char.isspace() for char in value):
        raise ScopeError("Use a valid http(s) URL without whitespace or control characters.")
    try:
        parsed = urlsplit(value)
        # Accessing .port validates malformed and out-of-range port values.
        port = parsed.port
        hostname = parsed.hostname
    except ValueError as exc:
        raise ScopeError("Use a valid http(s) URL with a valid host and port.") from exc
    if (
        parsed.scheme.lower() not in ("http", "https")
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ScopeError("Use an http(s) URL without embedded credentials.")
    if port == 0:
        raise ScopeError("Use a valid TCP port between 1 and 65535.")
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(normalize_http_url(value))
    return parsed.scheme, parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)


def enforce_same_origin(base: str, candidate: str) -> str:
    normalized = normalize_http_url(candidate)
    if origin(base) != origin(normalized):
        raise ScopeError("Out-of-scope URL blocked (same-origin only).")
    return normalized


def enforce_allowlist(endpoint: str, allowlist: list[str]) -> str:
    normalized = normalize_http_url(endpoint)
    if not isinstance(allowlist, (list, tuple)):
        raise ScopeError("Active validation requires an explicit endpoint allowlist.")
    if any(not isinstance(item, str) for item in allowlist):
        raise ScopeError("Active validation allowlist entries must be URLs.")
    approved = {normalize_http_url(item) for item in allowlist if item.strip()}
    if not approved or normalized not in approved:
        raise ScopeError("Active validation blocked: endpoint is not in the explicit allowlist.")
    return normalized


_SENSITIVE_QUERY_NAMES = {
    "token", "accesstoken", "refreshtoken", "apikey", "key", "secret",
    "signature", "sig", "authorization", "auth", "password", "passwd",
    "credential", "credentials", "session", "sessionid", "code",
    "instrumentationkey",
}

def redact_sensitive_url(value: str) -> str:
    """Mask common secret-bearing query values before displaying or exporting URLs."""
    try:
        parsed = urlsplit(value)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
    except (TypeError, ValueError):
        return value
    if not pairs:
        return value
    safe_pairs = []
    for key, item in pairs:
        canonical_key = re.sub(r"[^a-z0-9]", "", key.lower())
        sensitive = canonical_key in _SENSITIVE_QUERY_NAMES or canonical_key.endswith(
            ("token", "secret", "signature", "credential", "password", "authorization")
        )
        safe_pairs.append((key, "[REDACTED]" if sensitive else item))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(safe_pairs), parsed.fragment))


def redact_urls_in_text(value: str) -> str:
    """Redact sensitive query values in URLs embedded in human-readable diagnostics."""
    if not isinstance(value, str):
        return value
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

    def replace(match):
        raw = match.group(0)
        core = raw.rstrip(".,);]")
        return redact_sensitive_url(core) + raw[len(core):]

    return url_pattern.sub(replace, value)
