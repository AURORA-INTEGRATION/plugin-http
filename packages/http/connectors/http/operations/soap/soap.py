"""HTTP connector — SOAP / WSDL operation (POST a raw XML envelope)."""
from __future__ import annotations

from aurora_engine.connector_helper import get_connector_config

from connectors.http.client import auth_from_input, soap


def run(input: dict, context: dict) -> dict:
    alias = input.get("http_alias")
    config = get_connector_config("http", alias) if alias else {}
    return soap(
        config,
        path=input.get("url", ""),
        soap_action=input.get("soap_action"),
        body=input.get("body", ""),
        headers=input.get("headers"),
        auth=auth_from_input(input),
    )
