# plugin-http

Aurora connector plugin — **HTTP** (generic: REST, SOAP/WSDL, GraphQL).

Unlike `plugin-rest` (one service per verb, auth on the instance), this connector
is a single **parametric** request service plus SOAP and GraphQL helpers, and
**authentication is passed per call as flow input** — never stored on the
connector.

## Operations
- `request` — generic HTTP call, `method` parameter (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS).
- `soap` — POST a raw SOAP/WSDL XML envelope (+ optional SOAPAction).
- `graphql` — POST a query/mutation with variables.

## Helper services (flow-callable)
No HTTP call — they build the inputs for the operations above, usable as nodes in
the flow builder:
- `buildAuth` — assemble + **validate** the `auth` object (errors on missing
  fields, e.g. bearer without token). Output `auth` → feed the `auth` input.
- `buildHeaders` — merge header pairs, drop `None`, stringify. Output `headers`.
- `buildParams` — merge query-param pairs, drop `None` (keeps value types). Output `params`.

## Auth (flow input)
Pass a single **`auth` object** (recommended). It is **validated** before the
request — a type with missing fields raises a clear error instead of silently
sending an unauthenticated call.

| `type`     | required fields              |
|------------|------------------------------|
| `none`     | — (anonymous)                |
| `bearer`   | `token`                      |
| `basic`    | `username`, `password`       |
| `digest`   | `username`, `password`       |
| `api_key`  | `header_name`, `value`       |
| `custom`   | `header_name`, `value`       |

```yaml
auth: { type: bearer, token: "${input.token}" }
auth: { type: basic,  username: "${globals.user}", password: "${globals.pass}" }
auth: { type: api_key, header_name: X-Api-Key, value: "${input.key}" }
```

**Legacy:** the flat `auth_type` / `auth_value` / `auth_username` / `auth_password`
/ `auth_header_name` inputs still work (pre-1.1 flows), now also covering
`custom` and `digest`.

## Error handling
Set **`raise_for_status: true`** to turn a `>= 400` response into a structured
`HttpError` (method, url, status, short body) instead of a normal result. Transport
failures (connect/timeout) always raise `HttpError` (status `None`). Default is
`false` — the call returns `{status_code, headers, body}` as before.

## Utils (`connectors.http.utils`)
For `python_service` authors: `build_headers(...)` / `build_params(...)` (merge +
drop `None` + stringify), `redact_headers(...)` (mask credential values as `***`
before logging), and auth builders `bearer()`, `basic()`, `digest()`,
`api_key()`, `custom()`.

## Connector fields
`base_url` (optional; paths are relative, absolute path overrides), `default_headers`,
`timeout`, `verify_tls`, plus mTLS (`ca_cert`, `client_cert`, `client_key`). No credentials.

## Install
Git Source → `https://github.com/AURORA-INTEGRATION/plugin-http`, branch `main`,
subfolder `packages`. Registers connector type `http` and services
`common.connectors.http.*`.
