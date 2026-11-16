# Security

Report a suspected vulnerability privately to the AgenticOS maintainers through
[GitHub private vulnerability reporting](https://github.com/vstorm-co/agenticos-bridge/security/advisories/new).
Do not include real authorization codes, tokens, client secrets or configuration files
in public issues. Revoke affected provider grants and rotate compromised server secrets.

## Threat boundaries

The broker, its TLS terminator, host administrators, signing/encryption key and provider
apps are trusted. Self-hosted callers, callback parameters and provider HTTP responses
are untrusted. Access requires a secret deployment key issued through the local CLI after review,
bound to an exact origin, approved providers and expiry. No wildcard or public
self-registration exists. Only key hashes and enrollment/contact metadata persist in
a private SQLite registry; no OAuth account tokens persist. The API opens the registry
read-only. A stolen deployment key can impersonate its enrollment, so origin binding
is a callback restriction, not cryptographic proof of server ownership. PKCE still
protects handoff redemption. A malicious approved deployment can obtain tokens for
users who consent to it: users must trust the destination instance.

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
at the provider when needed. The console can revoke a deployment enrollment to block subsequent starts, callbacks,
exchanges and refreshes. This does not retract already issued provider tokens or stop
in-flight provider calls. There is no per-account bridge kill switch: revoke the
provider grant or rotate the bridge ticket key/app credentials when necessary.
The service cannot hide transient tokens from its own host operator. No claim of
zero knowledge, perfect security, provider approval, or completed independent audit is made.


## Compromise and operational response

An attacker controlling the process, host or TLS terminator can steal tokens as they
pass through authorization or refresh, even though no token database exists. They may
also steal shared application secrets and the ticket key. Encryption does not protect
a running process from its own operator or host compromise.

Restrict shell access, patch host/container dependencies, protect registry backups and
server secrets, and independently review the implementation before broader use. On
suspected compromise, stop new flows and renewals, preserve redacted evidence, contact
provider security teams, revoke affected grants and rotate compromised keys. Inform
approved deployment contacts and evaluate regulatory/contractual notifications with
Vstorm's privacy/security owners. Do not add payload logging to investigate.

The invitation model limits exposure; it does not waive privacy duties or liability.
The hosted-service legal basis, controller/processor roles, any Article 28 agreement,
subprocessors/transfers, retention and breach procedure need qualified review before
production approval. Public source licensing is not a substitute for hosted-service
terms. Record the actual agreement/review reference when issuing a key; do not invent
an approval or treat OAuth consent as blanket GDPR consent.
