"""HTTP connector helper — build a validated `auth` object for request/soap/graphql.

Assembles the single `auth` descriptor from form fields and validates it, so a
flow author gets a fail-fast error (e.g. bearer without token) at this step
instead of a silent unauthenticated call later.
"""
from __future__ import annotations

from connectors.http.utils import validate_auth


def run(input: dict, context: dict) -> dict:
    auth: dict = {"type": (input.get("type") or "none")}
    for k in ("token", "username", "password", "header_name", "value"):
        v = input.get(k)
        if v is not None and v != "":
            auth[k] = v

    validate_auth(auth)  # raises ValueError with a clear message on missing fields
    return {"auth": auth}
