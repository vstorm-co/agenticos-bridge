# Security

Report a suspected vulnerability privately to the AgenticOS maintainers through
[GitHub private vulnerability reporting](https://github.com/vstorm-co/agenticos-bridge/security/advisories/new).
Do not include real authorization codes, tokens, client secrets or configuration files
in public issues. Revoke affected provider grants and rotate compromised server secrets.

## Threat boundaries

The broker, its TLS terminator, host administrators, signing/encryption key and provider
apps are trusted. Self-hosted callers, callback parameters and provider HTTP responses
are untrusted. The protocol does not authenticate the identity of arbitrary deployments;
exact-origin enrollment controls which deployments may start consent. Public enrollment
allows anyone to request the allowlisted provider scopes under this app's identity.
A malicious enrolled deployment can obtain tokens for users who consent to it. Users
must trust the destination AgenticOS deployment. PKCE protects against theft of the
handoff ticket; it cannot make a malicious destination safe.

Fernet from cryptography provides authenticated encryption of all protocol tickets.
No custom cipher or unauthenticated encryption is used. Tickets bind purpose, issuer,
provider, configured client ID and lifetime. Refresh receipts contain a token digest,
not its plaintext. Transport requires TLS outside loopback and the single-host Docker
network. OAuth app secrets exist only in server configuration; OAuth account tokens
exist transiently in memory and are returned to the caller's encrypted Vault.

The bridge has no durable replay database. Provider authorization codes are single-use;
AgenticOS consumes its pending flow under an owner lock. Refresh tokens follow each
provider's own rotation/revocation semantics. Google refresh tokens may remain reusable;
receipts do not turn them into single-use tokens. Unknown-acceptance timeouts are not
retried inside the bridge. Callers must not blindly retry rotating refresh tokens.

Deleting a local account does not revoke its provider-side grant automatically. Revoke
at the provider when needed. Without a server token database there is no per-account
bridge kill switch: revoke the provider grant or rotate the bridge key/app credentials.
The service cannot hide transient tokens from its own host operator. No claim of
zero knowledge, perfect security, provider approval, or completed independent audit is made.
