---
name: provider-app-setup
description: Register or prepare a Google, Microsoft, Slack or other shared OAuth app for AgenticOS Bridge, including branding, allowed redirects, provider verification and secure server credential delivery. Use for authorized provider-console operations, not ordinary API adapter changes.
---

# Register a shared provider application

Read the bridge `README.md` and `SECURITY.md`, then current official provider
requirements. The skill grants no external authority: use the user's requested
accounts, organizations and submission scope. The user handles sign-in, MFA and
CAPTCHA challenges. Never bypass browser security barriers or invent compliance
statements, domain ownership, approval status or a completed security assessment.

## Prepare before submitting

Use a fresh, company-owned project/app for a new service. Keep production and test
apps separate where the provider requires it. Do not attach billing or add paid
services without an authorized need. Keep ownership in the intended organization;
do not add broad IAM roles, application permissions or domain-wide delegation as
a convenience for a delegated user-consent flow.

Check public HTTPS, homepage, privacy policy, terms, support contact, canonical
AgenticOS logo and domain ownership. Public pages describe this deployment's real
operator and data flow. Self-hosted operators must replace Vstorm-specific legal
content. Verification may require DNS proof, a demonstration video, publisher
identity or an independent assessment; record the actual blocker and ask the owner
for the missing proof instead of making it up.

Use the exact configured callback `/v1/oauth/callback/<provider>` on the bridge's
public HTTPS origin. It is a web/confidential app, not the Google desktop client
or a sign-in client for the AgenticOS console. No JavaScript origin is needed for
a server-only exchange unless the provider explicitly requires one.

Request only the products/scopes implemented in `scopes.json` and justified by
AgenticOS operations. Read-only consent remains the default; application-level
scope configuration does not authorize all users or automatically enable writes.
Google restricted scopes, Microsoft tenant/admin consent and Slack distribution
rules still apply. Slack's public-client PKCE mode is a different app contract
from this confidential web-app implementation.

## Credentials and readiness

Prefer the provider's official credential download when available. Transfer
credentials through protected files/stdin into server config; never print them,
commit downloads, paste secrets into chat or put them in URLs. If a UI-only secret
cannot be transferred safely with available tools, let the owner place it directly
in the server configuration. User account tokens belong only in local Vault.

Configure both client ID and secret without overwriting the ticket encryption key
or other provider configuration. Restart only the bridge, verify `/v1/providers`
and run a real consent/identity/refresh/revocation exercise on an authorized test
account. A configured provider is not necessarily verified or publicly approved.
Keep exact-origin enrollment closed to unreviewed destinations until the shared
application's distribution and security review are complete.

For submission, use truthful descriptions of transient bridge token processing
and direct self-hosted data access. Record the provider's actual submitted/pending
status and review reference without secrets. Do not claim a draft was submitted.


Deployment access is invitation-only. Read README's console access procedure. Use
`python -m agenticos_bridge.cli` to initialize, issue, list or revoke access; no HTTP
management exists. Keep the private registry and its revocations across releases.
Do not issue a production key without an actual reviewed request/agreement reference.
Keys bind one origin, provider allowlist and expiry; raw keys are displayed once and
must be delivered securely. CLI access must never persist or print OAuth account tokens.
