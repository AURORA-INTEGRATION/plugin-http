"""Shared HTTP client for the `http` connector.

One generic `request()` (any method) plus `soap()` and `graphql()` helpers.
Authentication is NOT stored on the connector: each call receives an `auth`
descriptor built from flow input (see `auth_from_input`).

TLS: the connector config may carry a custom CA and/or a client certificate
(mTLS), given either as a filesystem path or pasted PEM text — PEM is
materialized to a cached temp file for httpx.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from typing import Any

import httpx

_cert_cache: dict[str, str] = {}
_cert_lock = threading.Lock()


def _materialize(pem_or_path: Any) -> str | None:
    """Return a filesystem path for a cert given as PEM text or an existing path."""
    if not pem_or_path:
        return None
    s = str(pem_or_path)
    if "-----BEGIN" not in s:
        return s  # already a path
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
    """Return (verify, cert) kwargs for httpx from the connector TLS config."""
    verify: Any = bool(config.get("verify_tls", True))
    ca = _materialize(config.get("ca_cert"))
    if ca:
        verify = ca  # verify against custom CA bundle
    cert: Any = None
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


def _full_url(base: str, path: str | None) -> str:
    p = path or ""
    return p if p.startswith(("http://", "https://")) else base + p


def auth_from_input(inp: dict[str, Any]) -> dict[str, Any]:
    """Collect the flat auth_* input fields into an auth descriptor."""
    return {
        "type": inp.get("auth_type"),
        "value": inp.get("auth_value"),
        "username": inp.get("auth_username"),
        "password": inp.get("auth_password"),
        "header_name": inp.get("auth_header_name"),
    }


def _apply_auth(headers: dict[str, Any], auth: dict[str, Any] | None):
    """Mutate headers for bearer/api_key; return an httpx basic-auth tuple or None."""
    a = auth or {}
    t = (a.get("type") or "none").lower()
    if t == "bearer" and a.get("value"):
        headers["Authorization"] = f"Bearer {a['value']}"
    elif t == "api_key" and a.get("header_name"):
        headers[a["header_name"]] = a.get("value") or ""
    elif t == "basic":
        return (a.get("username") or "", a.get("password") or "")
    return None


def _coerce(body: Any) -> Any:
    """A JSON string (from the designer code editor) becomes a real object."""
    if isinstance(body, str):
        s = body.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except ValueError:
            return body
    return body


def request(
    config: dict[str, Any],
    method: str,
    path: str = "",
    params: dict[str, Any] | None = None,
    headers: dict[str, Any] | None = None,
    body: Any = None,
    auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base, base_headers, timeout = _prepare(config)
    verify, cert = _tls(config)
    url = _full_url(base, path)
    h = {**base_headers, **(headers or {})}
    httpx_auth = _apply_auth(h, auth)
    payload = _coerce(body)

    kwargs: dict[str, Any] = {"params": params or None, "headers": h, "auth": httpx_auth}
    if payload is not None and method.upper() not in ("GET", "HEAD"):
        if isinstance(payload, (dict, list)):
            kwargs["json"] = payload
        else:
            kwargs["content"] = str(payload)

    with httpx.Client(timeout=timeout, verify=verify, cert=cert) as cli:
        resp = cli.request(method.upper(), url, **kwargs)

    ct = resp.headers.get("content-type", "")
    out: Any = resp.json() if "json" in ct else resp.text
    return {"status_code": resp.status_code, "body": out, "headers": dict(resp.headers)}


def soap(
    config: dict[str, Any],
    path: str = "",
    soap_action: str | None = None,
    body: str = "",
    headers: dict[str, Any] | None = None,
    auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """POST a raw SOAP/WSDL envelope. `body` is the full XML envelope."""
    base, base_headers, timeout = _prepare(config)
    verify, cert = _tls(config)
    url = _full_url(base, path)
    h = {"Content-Type": "text/xml; charset=utf-8", **base_headers, **(headers or {})}
    if soap_action:
        h["SOAPAction"] = soap_action
    httpx_auth = _apply_auth(h, auth)

    with httpx.Client(timeout=timeout, verify=verify, cert=cert) as cli:
        resp = cli.post(url, content=str(body or "").encode("utf-8"), headers=h, auth=httpx_auth)
    return {"status_code": resp.status_code, "body": resp.text, "headers": dict(resp.headers)}


def graphql(
    config: dict[str, Any],
    path: str = "",
    query: str = "",
    variables: Any = None,
    headers: dict[str, Any] | None = None,
    auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base, base_headers, timeout = _prepare(config)
    verify, cert = _tls(config)
    url = _full_url(base, path)
    h = {**base_headers, **(headers or {})}
    httpx_auth = _apply_auth(h, auth)

    payload: dict[str, Any] = {"query": query}
    vars_ = _coerce(variables)
    if vars_ is not None:
        payload["variables"] = vars_

    with httpx.Client(timeout=timeout, verify=verify, cert=cert) as cli:
        resp = cli.post(url, json=payload, headers=h, auth=httpx_auth)
    ct = resp.headers.get("content-type", "")
    out: Any = resp.json() if "json" in ct else resp.text
    return {"status_code": resp.status_code, "body": out, "headers": dict(resp.headers)}


def test_connection(config: dict[str, Any]) -> dict[str, Any]:
    base, _, _ = _prepare(config)
    if not base:
        return {"ok": True, "note": "no base_url configured"}
    r = request(config, "GET", "")
    return {"ok": r["status_code"] < 500, "status_code": r["status_code"]}
