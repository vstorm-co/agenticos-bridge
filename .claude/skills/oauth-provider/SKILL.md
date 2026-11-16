---
name: oauth-provider
description: Add or change an OAuth provider adapter, token response normalization, scope allowlist, callback/PKCE protocol or refresh behavior in AgenticOS Bridge. Use for broker code, not for registering an app in a provider console.
---

# Extend the OAuth broker

Read `README.md`, `SECURITY.md` and `AGENTS.md`. This is a stateless OAuth broker,
not a general SaaS proxy or account database. Business API operations belong in
AgenticOS, not here. Provider registration is the `provider-app-setup` task.

Verify the provider's official code-flow and refresh documentation. Record fixed
authorization/token endpoints, confidential/public client type, PKCE support,
redirect requirements, scope encoding, actual user-token shape, rotation and
revocation semantics. Test real documented shapes, not a generic bearer payload:
Slack's nested `authed_user` and top-level rotated `user` token are different from
an installation's bot token.

## Owned seams

- `models.py`: public request/response types and provider discriminator.
- `config.py`: optional server app credentials, pair validation and public origin.
- `providers.py`: fixed outbound endpoints and provider-specific normalization.
- `scopes.json`: explicit product scopes; never accept arbitrary privileges.
- `service.py`: purpose/client/provider/callback/PKCE binding and refresh receipts.
- `tickets.py`: authenticated encryption and bounded ticket lifetimes.
- `tests/test_oauth.py`: protocol, refusal, response and static-page contracts.

Use `SecretStr` internally and reveal only at the deliberate token HTTP response
boundary. Do not echo rejected data in validation errors or provider failures.
Codes/tokens/receipts must stay out of logs, traces, URLs and unencrypted storage;
only encrypted, short-lived handoff tickets may travel in the browser callback.
A callback error must not be turned into successful account authorization.

A new provider needs the same token-bound refresh proof, code/client/purpose checks
and callback policy. Keep redirect following off, response/body limits and TLS
verification on. Do not retry unknown-acceptance code exchanges or rotating
refreshes. A provider without an appropriate code/refresh contract may need a
separate deliberate design; do not weaken proof checks to make it appear to work.

The matching AgenticOS adapter and account flow must be updated in its repository.
Do not copy a provider client secret there, give models raw credentials, silently
change existing credential sources or broaden account ownership.

Run scoped pytest, Ruff, ty and the pinned dependency audit. Cover provider denial,
bot substitution, malformed/large responses, mismatched provider/client/purpose,
expired/tampered tickets, wrong PKCE, rotated receipts and lost refresh responses.
Update provider setup and privacy/data-flow documentation when behavior changes.
Mocked protocol tests do not prove live consent or provider approval.


Deployment access is invitation-only. Read README's console access procedure. Use
`python -m agenticos_bridge.cli` to initialize, issue, list or revoke access; no HTTP
management exists. Keep the private registry and its revocations across releases.
Do not issue a production key without an actual reviewed request/agreement reference.
Keys bind one origin, provider allowlist and expiry; raw keys are displayed once and
must be delivered securely. CLI access must never persist or print OAuth account tokens.
