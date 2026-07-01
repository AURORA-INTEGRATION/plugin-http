"""HTTP connector helper — build a query-params object.

Merges `params` + `extra`, dropping None values (keeps value types so ints/bools/
lists serialise correctly). Feed the result into the `params` input of request.
"""
from __future__ import annotations

from connectors.http.utils import build_params


def run(input: dict, context: dict) -> dict:
    return {"params": build_params(input.get("params"), input.get("extra"))}
