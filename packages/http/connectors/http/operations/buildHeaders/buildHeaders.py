"""HTTP connector helper — build a headers object.

Merges `headers` + `extra`, dropping None values and stringifying, so a flow
author can assemble request headers in one step instead of chaining object
services. Feed the result into the `headers` input of request/soap/graphql.
"""
from __future__ import annotations

from connectors.http.utils import build_headers


def run(input: dict, context: dict) -> dict:
    return {"headers": build_headers(input.get("headers"), input.get("extra"))}
