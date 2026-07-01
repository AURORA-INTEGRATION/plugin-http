"""Utilities for the `http` connector.

Ergonomic builders (headers, query params, auth descriptors), a single-object
`auth` model with validation, and secret redaction. Flow authors and
python_services import these to avoid hand-assembling dicts and to fail fast on
misconfigured auth instead of silently sending an unauthenticated request.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

# Header names whose value is a credential and must never be logged / echoed.
SENSITIVE_HEADER_NAMES = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
})

_AUTH_TYPES = frozenset({"none", "bearer", "basic", "api_key", "custom", "digest"})


# ── Builders ────────────────────────────────────────────────────────────────

def build_headers(*sources: Mapping[str, Any] | None, **extra: Any) -> dict[str, str]:
    """Merge header dicts + keyword pairs into one dict, dropping ``None`` values
    and stringifying keys/values. Later sources win. Keeps header assembly in one
    call instead of nested ``{**a, **b}`` with manual None checks.

    >>> build_headers({"Accept": "application/json"}, X_Trace=None, Authorization="Bearer x")
    {'Accept': 'application/json', 'Authorization': 'Bearer x'}
    """
    out: dict[str, str] = {}
    for src in sources:
        if not src:
            continue
        for k, v in src.items():
            if v is None:
                continue
            out[str(k)] = str(v)
    for k, v in extra.items():
        if v is None:
            continue
        # kwargs can't contain '-', so allow '_' → '-' for convenience (X_Trace_Id).
        out[str(k).replace("_", "-")] = str(v)
    return out


def build_params(*sources: Mapping[str, Any] | None, **extra: Any) -> dict[str, Any]:
    """Merge query-param dicts + keyword pairs, dropping ``None`` values. Unlike
    headers, values keep their type (httpx serialises ints/bools/lists)."""
    out: dict[str, Any] = {}
    for src in sources:
        if not src:
            continue
        for k, v in src.items():
            if v is None:
                continue
            out[str(k)] = v
    for k, v in extra.items():
        if v is None:
            continue
        out[str(k)] = v
    return out


def redact_headers(headers: Mapping[str, Any] | None,
                   extra_names: Iterable[str] = ()) -> dict[str, str]:
    """Return a copy of ``headers`` with credential values masked as ``***``.
    Pass ``extra_names`` to also mask custom/api-key header names. Use before
    logging or storing request headers so tokens never hit run history."""
    if not headers:
        return {}
    mask = {n.lower() for n in SENSITIVE_HEADER_NAMES} | {n.lower() for n in extra_names}
    return {
        str(k): ("***" if str(k).lower() in mask else str(v))
        for k, v in headers.items()
    }


# ── Auth descriptors ────────────────────────────────────────────────────────

def bearer(token: str) -> dict[str, Any]:
    return {"type": "bearer", "token": token}


def basic(username: str, password: str) -> dict[str, Any]:
    return {"type": "basic", "username": username, "password": password}


def digest(username: str, password: str) -> dict[str, Any]:
    return {"type": "digest", "username": username, "password": password}


def api_key(header_name: str, value: str) -> dict[str, Any]:
    return {"type": "api_key", "header_name": header_name, "value": value}


def custom(header_name: str, value: str) -> dict[str, Any]:
    return {"type": "custom", "header_name": header_name, "value": value}


def normalize_auth(inp: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve the auth descriptor from flow input.

    Preferred: a single ``auth`` object. Falls back to the legacy flat fields
    (``auth_type``/``auth_value``/``auth_username``/``auth_password``/
    ``auth_header_name``) so pre-1.1 flows keep working unchanged.
    """
    obj = inp.get("auth")
    if isinstance(obj, Mapping):
        a = dict(obj)
        # `value` is accepted as an alias for a bearer token.
        if not a.get("token") and a.get("value") and (a.get("type") or "").lower() == "bearer":
            a["token"] = a["value"]
        return a

    return {
        "type": inp.get("auth_type"),
        "token": inp.get("auth_value"),
        "value": inp.get("auth_value"),
        "username": inp.get("auth_username"),
        "password": inp.get("auth_password"),
        "header_name": inp.get("auth_header_name"),
    }


def validate_auth(auth: Mapping[str, Any] | None) -> None:
    """Raise ``ValueError`` when an auth type is set but its required fields are
    missing — the whole point of the enterprise pass: no silent unauthenticated
    requests. ``none``/empty is valid (anonymous)."""
    a = auth or {}
    raw = a.get("type")
    t = (raw or "none").lower()

    if t in ("none", ""):
        return

    if t not in _AUTH_TYPES:
        raise ValueError(
            f"auth: unknown type '{raw}' (expected one of "
            f"{', '.join(sorted(_AUTH_TYPES))})"
        )

    if t == "bearer":
        if not (a.get("token") or a.get("value")):
            raise ValueError("auth bearer: 'token' is required")

    elif t in ("basic", "digest"):
        missing = [f for f in ("username", "password") if not a.get(f)]
        if missing:
            raise ValueError(f"auth {t}: {', '.join(missing)} required")

    elif t in ("api_key", "custom"):
        missing = []
        if not a.get("header_name"):
            missing.append("header_name")
        if not a.get("value"):
            missing.append("value")
        if missing:
            raise ValueError(f"auth {t}: {', '.join(missing)} required")
