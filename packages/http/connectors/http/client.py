"""
Shared HTTP client for the `http` connector.

One generic `request()` (any method) plus `soap()` and `graphql()` helpers.
Authentication is NOT stored on the connector: each call receives a single
`auth` descriptor built from flow input (see `utils.normalize_auth`), which is
validated before the request so a misconfigured auth fails fast instead of
silently going out unauthenticated.

TLS: supports custom CA and client certificates (mTLS).
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from typing import Any

import httpx

from connectors.http.utils import (  # noqa: F401 — re-exported for python_services
    api_key,
    basic,
    bearer,
    build_headers,
    build_params,
    custom,
    digest,
    normalize_auth,
    redact_headers,
    validate_auth,
)


_cert_cache: dict[str, str] = {}
_cert_lock = threading.Lock()


# ── Errors ──────────────────────────────────────────────────────────────────

class HttpError(Exception):
    """Raised for a failed HTTP call: a transport failure (no response) or, when
    `raise_for_status` is set, a >= 400 status. Carries structured fields and a
    message that never includes credentials (only method/url/status/short body)."""

    def __init__(self, method: str, url: str, status_code: int | None,
                 body: str = "", reason: str | None = None) -> None:
        self.method = (method or "").upper()
        self.url = url
        self.status_code = status_code
        self.body = body
        self.reason = reason
        if status_code is not None:
            msg = f"HTTP {status_code} on {self.method} {url}"
        else:
            msg = f"HTTP request failed on {self.method} {url}: {reason or 'transport error'}"
        if body:
            msg = f"{msg} — {body}"
        super().__init__(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "reason": self.reason,
            "body": self.body,
        }


# ── TLS / cert materialisation ──────────────────────────────────────────────

def _materialize(pem_or_path: Any) -> str | None:
    if not pem_or_path:
        return None

    s = str(pem_or_path)

    if "-----BEGIN" not in s:
        return s

    key = hashlib.sha1(s.encode("utf-8")).hexdigest()[:16]

    cached = _cert_cache.get(key)
    if cached and os.path.exists(cached):
        return cached

    with _cert_lock:
        cached = _cert_cache.get(key)
        if cached and os.path.exists(cached):
            return cached

        fd, path = tempfile.mkstemp(suffix=".pem", prefix="aurora-cert-")
        with os.fdopen(fd, "w") as fh:
            fh.write(s)

        _cert_cache[key] = path
        return path


def _tls(config: dict[str, Any]):
    verify: Any = config.get("verify_tls", True)

    ca = _materialize(config.get("ca_cert"))
    if ca:
        verify = ca

    cert = None
    cc = _materialize(config.get("client_cert"))
    ck = _materialize(config.get("client_key"))

    if cc:
        cert = (cc, ck) if ck else cc

    return verify, cert


def _prepare(config: dict[str, Any]):
    base = (config.get("base_url") or "").rstrip("/")
    headers = dict(config.get("default_headers") or {})

    try:
        timeout = float(config.get("timeout") or 30)
    except (TypeError, ValueError):
        timeout = 30.0

    return base, headers, timeout


def _resolve_url(base: str, url: str | None, path: str | None) -> str:
    chosen = (url or base or "").rstrip("/")
    if path:
        return f"{chosen}/{path.lstrip('/')}"
    return chosen


# ── Auth ────────────────────────────────────────────────────────────────────

# Backward-compat alias: operations still import `auth_from_input`.
auth_from_input = normalize_auth


def _apply_auth(headers: dict[str, Any], auth: dict[str, Any] | None):
    """Apply a *validated* auth descriptor. Header-based types mutate `headers`
    and return None; basic/digest return an httpx auth object for `auth=`."""
    a = auth or {}
    t = (a.get("type") or "none").lower()

    if t == "bearer":
        headers["Authorization"] = f"Bearer {a.get('token') or a.get('value')}"

    elif t in ("api_key", "custom"):
        headers[a["header_name"]] = a.get("value") or ""

    elif t == "basic":
        return (a.get("username") or "", a.get("password") or "")

    elif t == "digest":
        return httpx.DigestAuth(a.get("username") or "", a.get("password") or "")

    return None


# ── Response / execution ────────────────────────────────────────────────────

def _coerce(body: Any) -> Any:
    if isinstance(body, str):
        s = body.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except ValueError:
            return body
    return body


_TEXT_HINTS = (
    "text/",
    "json",
    "xml",
    "html",
    "javascript",
    "ecmascript",
    "x-www-form-urlencoded",
    "csv",
)


def _response(resp: httpx.Response) -> dict[str, Any]:
    ct = (resp.headers.get("content-type") or "").lower()

    if "json" in ct:
        body = resp.json()

    elif any(h in ct for h in _TEXT_HINTS):
        body = resp.text

    else:
        # PDF, immagini, zip, binary -> SEMPRE bytes
        body = resp.content

    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "body": body,
    }


def _short_body(resp: httpx.Response, limit: int = 500) -> str:
    try:
        t = (resp.text or "").strip().replace("\n", " ")
    except Exception:
        return ""
    return t[:limit] + ("…" if len(t) > limit else "")


def _send(method: str, target: str, timeout: float, verify: Any, cert: Any,
          raise_for_status: bool, **kwargs: Any) -> httpx.Response:
    """Execute the request, normalising failures into `HttpError`: transport
    errors (connect/timeout) become an HttpError with no status; >= 400 responses
    raise only when `raise_for_status` is set."""
    m = method.upper()
    try:
        with httpx.Client(timeout=timeout, verify=verify, cert=cert) as client:
            resp = client.request(m, target, **kwargs)
    except httpx.HTTPError as exc:
        raise HttpError(m, target, None, reason=f"{type(exc).__name__}: {exc}") from exc

    if raise_for_status and resp.status_code >= 400:
        raise HttpError(m, target, resp.status_code, body=_short_body(resp))

    return resp


# ── Operations ──────────────────────────────────────────────────────────────

def request(
    config: dict[str, Any],
    method: str,
    url: str = "",
    path: str = "",
    params: dict[str, Any] | None = None,
    headers: dict[str, Any] | None = None,
    body: Any = None,
    auth: dict[str, Any] | None = None,
    raise_for_status: bool = False,
) -> dict[str, Any]:
    validate_auth(auth)

    base, base_headers, timeout = _prepare(config)
    verify, cert = _tls(config)

    target = _resolve_url(base, url, path)

    h = build_headers(base_headers, headers)
    httpx_auth = _apply_auth(h, auth)

    payload = _coerce(body)

    kwargs: dict[str, Any] = {
        "params": params,
        "headers": h,
        "auth": httpx_auth,
    }

    if payload is not None and method.upper() not in ("GET", "HEAD"):
        if isinstance(payload, (dict, list)):
            kwargs["json"] = payload
        elif isinstance(payload, (bytes, bytearray)):
            kwargs["content"] = payload
        else:
            kwargs["content"] = str(payload).encode("utf-8")

    resp = _send(method, target, timeout, verify, cert, raise_for_status, **kwargs)
    return _response(resp)


def soap(
    config: dict[str, Any],
    url: str = "",
    path: str = "",
    soap_action: str | None = None,
    body: str = "",
    headers: dict[str, Any] | None = None,
    auth: dict[str, Any] | None = None,
    raise_for_status: bool = False,
) -> dict[str, Any]:
    validate_auth(auth)

    base, base_headers, timeout = _prepare(config)
    verify, cert = _tls(config)

    target = _resolve_url(base, url, path)

    h = build_headers({"Content-Type": "text/xml; charset=utf-8"}, base_headers, headers)
    if soap_action:
        h["SOAPAction"] = soap_action

    httpx_auth = _apply_auth(h, auth)

    resp = _send(
        "POST", target, timeout, verify, cert, raise_for_status,
        content=str(body or "").encode("utf-8"), headers=h, auth=httpx_auth,
    )

    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "body": resp.text,
    }


def graphql(
    config: dict[str, Any],
    url: str = "",
    path: str = "",
    query: str = "",
    variables: Any = None,
    headers: dict[str, Any] | None = None,
    auth: dict[str, Any] | None = None,
    raise_for_status: bool = False,
) -> dict[str, Any]:
    validate_auth(auth)

    base, base_headers, timeout = _prepare(config)
    verify, cert = _tls(config)

    target = _resolve_url(base, url, path)

    h = build_headers(base_headers, headers)
    httpx_auth = _apply_auth(h, auth)

    payload: dict[str, Any] = {"query": query}

    vars_ = _coerce(variables)
    if vars_ is not None:
        payload["variables"] = vars_

    resp = _send(
        "POST", target, timeout, verify, cert, raise_for_status,
        json=payload, headers=h, auth=httpx_auth,
    )
    return _response(resp)


def test_connection(config: dict[str, Any]) -> dict[str, Any]:
    base, _, _ = _prepare(config)

    if not base:
        return {"ok": True, "note": "no base_url configured"}

    r = request(config, "GET", "")

    return {
        "ok": r["status_code"] < 500,
        "status_code": r["status_code"],
    }
