# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/mechubsec/rustmistmcp/security/advisories/new

(Security tab → "Report a vulnerability", or the link above.) Include what you'd include in a bug report — affected version, reproduction steps, and impact — but keep it in the private report, not a public issue, PR, or discussion.

## Scope

This is an MCP server that authenticates to the Juniper Mist cloud API with an operator-supplied bearer credential and exposes a bounded, scoped tool surface — including a guarded plan → digest → approve → apply lifecycle for WAN-edge configuration changes — to MCP clients. Vulnerability classes we especially want to hear about:

- Authentication or authorization bypass, including MCP bearer-token scope enforcement and org/site scoping
- Any path that lets a change set be applied without going through plan → digest → approve → apply, or without independent second-principal approval outside of explicit, operator-enabled `--lab-mode`
- Request/response bounds bypass — anything that lets an unbounded or oversized payload (from a compromised or misbehaving upstream) reach a caller or exhaust server resources
- Credential handling issues: the Mist API token or an MCP bearer token appearing in logs, audit records, error messages, or process arguments
- TLS, Host, or Origin enforcement bypass on the HTTP transport

## Response

This is a community-maintained project. There's no guaranteed SLA. A human maintainer is responsible for triaging every report and for all disclosure and fix decisions.
