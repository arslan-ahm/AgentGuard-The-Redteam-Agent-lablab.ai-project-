"""Secret redaction (brief 6.9, 6.3, 10). Owner: Arslan.

Applied to everything that leaves a trust boundary: audit events, sandbox evidence
(``network_summary.json``, ``console.json``, ``policy_events``) and any page content sent to
the LLM. Two layers:

- :func:`redact` walks dicts/lists and blanks the **value** of any key that names a secret
  (``password``, ``token``, ``authorization``, ``cookie``, ``api_key``...).
- :func:`redact_text` rewrites secret-looking substrings inside free text: bearer/basic auth,
  JWTs, cloud and SaaS keys, private keys, credentials in URLs, secret query parameters,
  ``Cookie``/``Set-Cookie`` values, ``password=...`` pairs and DB connection strings.

Names are kept and only values are replaced, so evidence still says *what* leaked.
Every pattern is bounded, so redaction stays linear on hostile input.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
MAX_TEXT = 1_000_000  # longer strings are truncated before scanning

_SECRET_KEY = re.compile(
    r"(?i)^(?:x[-_])?(?:pass(?:word|wd|phrase)?|pwd|secret|client[-_]?secret|token|"
    r"access[-_]?token|refresh[-_]?token|id[-_]?token|auth|authorization|"
    r"proxy[-_]authorization|cookie|set[-_]cookie|session(?:[-_]?id)?|sid|csrf(?:[-_]?token)?|"
    r"xsrf(?:[-_]?token)?|api[-_]?key|apikey|private[-_]?key|access[-_]?key|"
    r"secret[-_]?key|credentials?|jwt|bearer|otp|pin|signature|sig)$"
)
"""Keys whose values are always secret (exact names, case-insensitive)."""

_SECRET_KEY_PART = re.compile(r"(?i)(password|passwd|secret|token|api[-_]?key|private[-_]?key)")
"""Substrings that make a longer key secret too (``db_password``, ``githubToken``)."""

_SENSITIVE_PARAM_NAMES = (
    r"(?:access_token|refresh_token|id_token|token|auth|api_?key|apikey|key|password|passwd|"
    r"pwd|secret|client_secret|session(?:_?id)?|sid|jsessionid|phpsessid|code|signature|sig|"
    r"x-amz-signature|x-amz-credential|x-goog-signature)"
)

# (pattern, replacement) pairs, applied in order. Group 1 (when present) is kept.
_TEXT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # PEM private keys (bounded body)
    (
        re.compile(
            r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----[\s\S]{0,8000}?-----END [A-Z ]{0,30}"
            r"PRIVATE KEY-----"
        ),
        "-----BEGIN PRIVATE KEY-----" + REDACTED + "-----END PRIVATE KEY-----",
    ),
    # Authorization headers / bearer and basic credentials
    (
        re.compile(r"(?i)\b((?:proxy-)?authorization\s*[:=]\s*)[^\r\n]{1,2000}"),
        r"\1" + REDACTED,
    ),
    # "Bearer abc123..." / "Basic dXNlcjpw..." (a digit is required so prose like "basic
    # authentication" is left alone)
    (
        re.compile(
            r"(?i)\b(bearer|basic)\s+(?=[A-Za-z0-9._~+/=-]{0,4096}\d)[A-Za-z0-9._~+/=-]{8,4096}"
        ),
        r"\1 " + REDACTED,
    ),
    # Cookie / Set-Cookie header values (names of cookies are lost on purpose: one line)
    (re.compile(r"(?i)\b((?:set-)?cookie\s*:\s*)[^\r\n]{1,4000}"), r"\1" + REDACTED),
    # JWTs
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,4000}\.[A-Za-z0-9_-]{5,8000}\.[A-Za-z0-9_-]{0,4000}"),
        REDACTED,
    ),
    # Well-known key formats
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"), REDACTED),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,255}\b"), REDACTED),
    (re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,255}\b"), REDACTED),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,255}\b"), REDACTED),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), REDACTED),
    (re.compile(r"\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{10,255}\b"), REDACTED),
    # Credentials inside URLs: scheme://user:pass@host  ->  scheme://[REDACTED]@host
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,20}://)[^\s/@:]{1,256}:[^\s/@]{1,256}@"),
        r"\1" + REDACTED + "@",
    ),
    # Secret query / form parameters: ?token=abc&x=1  ->  ?token=[REDACTED]&x=1
    (
        re.compile(r"(?i)([?&;](?:" + _SENSITIVE_PARAM_NAMES + r")=)[^&#\s\"'<>]{1,4096}"),
        r"\1" + REDACTED,
    ),
    # key=value / key: value pairs in text, JSON and form bodies
    (
        re.compile(
            r"(?i)([\"']?\b(?:password|passwd|pwd|secret|client_secret|api_?key|access_token|"
            r"refresh_token|private_key)[\"']?\s*[:=]\s*[\"']?)[^\s\"'&,;}]{1,4096}"
        ),
        r"\1" + REDACTED,
    ),
)


def is_secret_key(key: str) -> bool:
    """True if a mapping key names a secret value."""
    return bool(_SECRET_KEY.match(key) or _SECRET_KEY_PART.search(key))


def redact_text(text: str) -> str:
    """Replace secret-looking substrings in ``text``. Linear time; never raises."""
    if not text:
        return text
    out = text[:MAX_TEXT]
    for pattern, replacement in _TEXT_RULES:
        out = pattern.sub(replacement, out)
    return out


def redact(value: Any, _depth: int = 0) -> Any:
    """Return a redacted deep copy of ``value`` (dicts, lists, tuples, strings)."""
    if _depth > 50:  # pathological nesting: drop rather than recurse forever
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and is_secret_key(key) and item not in (None, "", [], {}):
                out[key] = REDACTED
            else:
                out[key] = redact(item, _depth + 1)
        return out
    if isinstance(value, list | tuple):
        items = [redact(v, _depth + 1) for v in value]
        return items if isinstance(value, list) else tuple(items)
    return value


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Header dict with secret headers (Authorization, Cookie, tokens...) blanked."""
    return {k: (REDACTED if is_secret_key(k) else redact_text(v)) for k, v in headers.items()}
