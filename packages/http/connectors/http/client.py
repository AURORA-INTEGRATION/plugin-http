"""Shared HTTP client for the `http` connector.

One generic `request()` (any method) plus `soap()` and `graphql()` helpers.
Authentication is NOT stored on the connector: each call receives an `auth`
descriptor built from flow input (see `auth_from_input`).
"""
from __future__ import annotations

import json
from typing import Any

import httpx


def _prepare(config: dict[str, Any]):
    base = (config.get("base_url") or "").rstrip("/")
    headers = dict(config.get("default_headers") or {})
    try:
        timeout = float(config.get("timeout") or 30)
    except (TypeError, ValueError):
        timeout = 30.0
    return base, headers, timeout, bool(config.get("verify_tls", True))


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
    base, base_headers, timeout, verify = _prepare(config)
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

    with httpx.Client(timeout=timeout, verify=verify) as cli:
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
    base, base_headers, timeout, verify = _prepare(config)
    url = _full_url(base, path)
    h = {"Content-Type": "text/xml; charset=utf-8", **base_headers, **(headers or {})}
    if soap_action:
        h["SOAPAction"] = soap_action
    httpx_auth = _apply_auth(h, auth)

    with httpx.Client(timeout=timeout, verify=verify) as cli:
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
    base, base_headers, timeout, verify = _prepare(config)
    url = _full_url(base, path)
    h = {**base_headers, **(headers or {})}
    httpx_auth = _apply_auth(h, auth)

    payload: dict[str, Any] = {"query": query}
    vars_ = _coerce(variables)
    if vars_ is not None:
        payload["variables"] = vars_

    with httpx.Client(timeout=timeout, verify=verify) as cli:
        resp = cli.post(url, json=payload, headers=h, auth=httpx_auth)
    ct = resp.headers.get("content-type", "")
    out: Any = resp.json() if "json" in ct else resp.text
    return {"status_code": resp.status_code, "body": out, "headers": dict(resp.headers)}


def test_connection(config: dict[str, Any]) -> dict[str, Any]:
    base, _, _, _ = _prepare(config)
    if not base:
        return {"ok": True, "note": "no base_url configured"}
    r = request(config, "GET", "")
    return {"ok": r["status_code"] < 500, "status_code": r["status_code"]}
