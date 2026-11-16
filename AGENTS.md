# AgenticOS Bridge

Stateless OAuth API; Python 3.15, FastAPI, Pydantic, httpx, cryptography.
Read README.md and SECURITY.md before changing protocol behavior.

- Routes adapt HTTP; OAuthService owns the flow; ProviderClient owns fixed provider transport.
- No database, frontend, generic URL proxy, user-token persistence, or request-body logging.
- Use cryptography's authenticated encryption. Never invent crypto primitives.
- No retries of authorization-code exchange or rotating refresh after unknown acceptance.
- Credentials and ticket keys are secrets. Keep them out of git, errors and logs.
- Validate callback, purpose, expiry, issuer, provider, client ID and PKCE before provider I/O.
- Fully type owned boundaries. Narrow unknown data; no Any or unchecked casts.
- Add refusal/regression tests for protocol changes. Run scoped pytest, ruff and ty.
- Work on a feature branch; Conventional Commits, no AI attribution.
