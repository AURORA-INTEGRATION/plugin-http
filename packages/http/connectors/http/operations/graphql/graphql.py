"""HTTP connector — GraphQL operation."""
from __future__ import annotations

from aurora_engine.connector_helper import get_connector_config

from connectors.http.client import auth_from_input, graphql


def run(input: dict, context: dict) -> dict:
    alias = input.get("http_alias")
    config = get_connector_config("http", alias) if alias else {}
    return graphql(
        config,
        path=input.get("path", ""),
        query=input.get("query", ""),
        variables=input.get("variables"),
        headers=input.get("headers"),
        auth=auth_from_input(input),
    )
