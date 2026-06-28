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

## Auth (flow input)
Each operation takes flat `auth_*` inputs (bind them to `${input.*}` / globals):
`auth_type` (none|bearer|basic|api_key), `auth_value` (token/api-key),
`auth_username`, `auth_password`, `auth_header_name`.

## Connector fields
`base_url` (optional; paths are relative, absolute path overrides), `default_headers`,
`timeout`, `verify_tls`. No credentials.

## Install
Git Source → `https://github.com/AURORA-INTEGRATION/plugin-http`, branch `main`,
subfolder `packages`. Registers connector type `http` and services
`common.connectors.http.*`.
