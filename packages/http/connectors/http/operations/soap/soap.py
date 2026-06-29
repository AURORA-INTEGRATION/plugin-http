"""HTTP connector — SOAP / WSDL operation.

Two ways to provide the request:
  * ``body``      — a ready-to-send SOAP envelope (raw XML). Power use / non-WSDL.
  * ``operation`` + ``namespace`` + ``payload`` — a structured request that is
    marshalled to a SOAP envelope at runtime. Handles nested objects and arrays
    (a list repeats its element), which a static string template can't express.
"""
from __future__ import annotations

from typing import Any
from xml.sax.saxutils import escape

from aurora_engine.connector_helper import get_connector_config

from connectors.http.client import auth_from_input, soap


def _marshal(value: Any, tag: str) -> str:
    """Recursively turn a value into namespace-qualified XML elements.

    dict → nested children · list → the element repeated per item · scalar → text.
    """
    if isinstance(value, dict):
        inner = "".join(_marshal(v, k) for k, v in value.items() if v is not None)
        return f"<tns:{tag}>{inner}</tns:{tag}>"
    if isinstance(value, (list, tuple)):
        return "".join(_marshal(v, tag) for v in value)
    if isinstance(value, bool):
        value = "true" if value else "false"
    return f"<tns:{tag}>{escape(str(value))}</tns:{tag}>"


def _build_envelope(operation: str, namespace: str | None, payload: Any) -> str:
    inner = ""
    if isinstance(payload, dict):
        inner = "".join(_marshal(v, k) for k, v in payload.items() if v is not None)
    elif payload is not None:
        inner = escape(str(payload))
    ns = escape(namespace or "", {'"': "&quot;"})
    request = f'<tns:{operation} xmlns:tns="{ns}">{inner}</tns:{operation}>'
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        f"<soapenv:Body>{request}</soapenv:Body></soapenv:Envelope>"
    )


def run(input: dict, context: dict) -> dict:
    alias = input.get("http_alias")
    config = get_connector_config("http", alias) if alias else {}

    body = input.get("body") or ""
    if not body:
        operation = input.get("operation")
        payload = input.get("payload")
        if operation:
            body = _build_envelope(operation, input.get("namespace"), payload)

    return soap(
        config,
        url=input.get("url", ""),
        path=input.get("path", ""),
        soap_action=input.get("soap_action"),
        body=body,
        headers=input.get("headers"),
        auth=auth_from_input(input),
    )
