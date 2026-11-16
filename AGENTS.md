# AgenticOS Bridge

Stateless OAuth API; Python 3.15, FastAPI, Pydantic, httpx, cryptography.
Read README.md and SECURITY.md before changing protocol behavior.

- Routes adapt HTTP; OAuthService owns the flow; ProviderClient owns fixed provider transport.
- Only the console-managed SQLite deployment-access registry may persist key hashes and enrollment metadata. No account dashboard, generic URL proxy, user-token persistence, or request-body logging. Public verification pages are static assets.
- Use cryptography's authenticated encryption. Never invent crypto primitives.
- No retries of authorization-code exchange or rotating refresh after unknown acceptance.
- Credentials and ticket keys are secrets. Keep them out of git, errors and logs.
- Validate callback, purpose, expiry, issuer, provider, client ID and PKCE before provider I/O.
- Fully type owned boundaries. Narrow unknown data; no Any or unchecked casts.
- Add refusal/regression tests for protocol changes. Run scoped pytest, ruff and ty.
- Work on a feature branch; Conventional Commits, no AI attribution.


## Coding agent entry points

`AGENTS.md` is canonical. `CLAUDE.md` links here for Claude Code. Skills live under
`.claude/skills/`; `.agents/skills` points there for Codex, and OpenCode discovers
the same compatibility paths. Keep one source and preserve links; no personal
model choices, MCP credentials or global permissions belong in this repository.

| Task | Skill |
| --- | --- |
| Provider code, grant normalization, callback/refresh security | `oauth-provider` |
| Shared app registration, branding and provider verification | `provider-app-setup` |
| Authorized VPS release, health/TLS and safe configuration | `bridge-deploy` |

AgenticOS capabilities and workflow nodes live in the AgenticOS repository. Use its
`native-integration`, `agent-capability` and `workflow-node` skills rather than
implementing business API calls or workflow execution in this broker.


## Deployment access

`access.py` owns the real SQLite registry; `cli.py` is its only mutation entry point.
Never add HTTP key issuance, public registration, a wildcard bypass or plaintext key
storage. Bind tickets/refresh receipts to enrollment IDs and check active access at
all protocol boundaries. A missing registry fails closed. Changes require real SQLite
and CLI tests in `tests/test_access.py`, alongside existing protocol tests.
