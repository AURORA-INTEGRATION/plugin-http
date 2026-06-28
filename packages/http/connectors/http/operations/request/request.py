"""HTTP connector — generic Request operation (any method)."""
from __future__ import annotations

from aurora_engine.connector_helper import get_connector_config

from connectors.http.client import auth_from_input, request


def run(input: dict, context: dict) -> dict:
    alias = input.get("http_alias")
    config = get_connector_config("http", alias) if alias else {}
    return request(
        config,
        input.get("method", "GET"),
        path=input.get("path", ""),
        params=input.get("params"),
        headers=input.get("headers"),
        body=input.get("body"),
        auth=auth_from_input(input),
    )
