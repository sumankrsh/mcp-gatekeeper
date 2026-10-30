# Changelog

## 0.1.0 (2026-10-30)

First release.

- `mcp-gatekeeper run`: a stdio proxy in front of one MCP server that checks every `tools/call` against a YAML policy (allow, deny or approve per tool, argument conditions, roles, rate limits) and hides always-denied tools from `tools/list`. Everything else passes through, so it works with handshake-era (up to 2025-11-25) and 2026-07-28 clients and servers.
- Human approvals through a folder of JSON files, answered with `approvals watch`, `approve` or `deny`. Unanswered calls are denied after `approval_timeout`.
- Hash-chained JSON Lines audit log, optionally HMAC-signed, with `audit verify`, `audit show` and `audit head`.
- Redaction of secrets and personal data (checksum-validated for IBANs and card numbers) in the log and approval requests.
- `validate` and `explain` for checking policies without running a server.
- `demo`: a scripted agent against a fake payments server in `examples/`.
