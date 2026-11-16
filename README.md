<p align="center"><img src="src/agenticos_bridge/public/assets/logo.svg" width="72" height="72" alt="AgenticOS"></p>

<h1 align="center">AgenticOS Bridge</h1>
<p align="center">Shared OAuth for your own AgenticOS instance.</p>

<p align="center">
<a href="https://github.com/vstorm-co/agenticos-bridge/actions/workflows/checks.yml"><img src="https://github.com/vstorm-co/agenticos-bridge/actions/workflows/checks.yml/badge.svg?branch=main" alt="Checks"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache 2.0 license"></a>
<a href="https://bridge-agenticos.testapp.ovh"><img src="https://img.shields.io/badge/service-HTTPS-green" alt="HTTPS service"></a>
</p>

**[Service](https://bridge-agenticos.testapp.ovh) · [Privacy](https://bridge-agenticos.testapp.ovh/privacy/) · [Support](https://bridge-agenticos.testapp.ovh/support/) · [Security](SECURITY.md)**

API-only OAuth broker for self-hosted [AgenticOS](https://github.com/vstorm-co/agenticos).
A deployment can use **Continue with AgenticOS**, or keep its own provider application
credentials and bypass this service completely. The service includes small public information, privacy, terms and support pages for provider verification. There is no account dashboard, account-token directory, business API proxy or user-token storage. A small SQLite access registry stores deployment-key hashes and reviewed enrollment/contact metadata only.

## Connect from AgenticOS

The native connected-account integration is tracked in
[AgenticOS #2805](https://github.com/vstorm-co/agenticos/pull/2805). Use a build that
contains that integration; do not assume an older released console already has it.

1. Email **dev@vstorm.co** with your organization, exact public AgenticOS origin,
   intended providers and a security/incident contact. Vstorm reviews requests individually;
   sending a request does not grant access. Complete the applicable terms/privacy and
   organizational agreement review before a production key is issued.
2. After approval, configure backend `OAUTH_BRIDGE_URL=https://bridge-agenticos.testapp.ovh`
   and `OAUTH_BRIDGE_ACCESS_KEY` using the issued secret. Both default to empty. Keep
   them in server-side secret configuration, never `NEXT_PUBLIC_*`, agent specs or git.
3. The option is hidden on ordinary installations. An approved deployment sees
   **Continue with AgenticOS** only for an allowed, configured provider.
4. Provider consent returns to your instance; account tokens stay in its Vault.

**Use your own credentials** keeps the organization's own OAuth app and bypasses
this service. Public provider verification is a separate readiness requirement;
configuration alone is not approval.

## Trust and data flow

1. AgenticOS creates a PKCE verifier and browser-bound pending flow in its local Vault.
2. `POST /v1/oauth/start` validates the provider, permitted scopes and deployment callback.
   It returns the provider's consent URL. The OAuth state is authenticated and encrypted.
3. The provider redirects to `/v1/oauth/callback/{provider}`. The bridge validates the
   state and redirects to AgenticOS with an encrypted, 90-second exchange ticket.
   Access and refresh tokens never appear in browser URLs.
4. AgenticOS calls `POST /v1/oauth/token` with the ticket and verifier. The bridge
   exchanges the single-use code at a fixed provider endpoint, then returns tokens
   over HTTPS. AgenticOS seals them in its own owner-bound Vault.
5. Business API calls go directly from AgenticOS to the provider. Refresh goes through
   `POST /v1/oauth/refresh`, requiring the token and an encrypted receipt bound to
   its SHA-256 digest, provider and client ID. Rotated tokens get new receipts.

Google and Microsoft use upstream S256 PKCE. Slack uses the confidential web-app flow
and client secret; the AgenticOS-to-bridge ticket redemption still requires S256 proof.
Do not enable Slack's public-client PKCE mode for this confidential-client setup.
The signed-in user, browser nonce, tenant permissions, scope ceilings and callback
single-use admission remain the AgenticOS deployment's responsibility.

## Run

Python 3.15 and uv are required.

```sh
cp .env.example .env
uv sync --frozen
uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
# Put that output in BRIDGE_TICKET_KEY; chmod 600 .env.
uv run uvicorn agenticos_bridge.main:create_app --factory --app-dir src \
  --host 127.0.0.1 --port 8060 --no-access-log --no-proxy-headers
```

`GET /healthz` reports process health. `GET /v1/providers` reports which apps are
configured and their exact callback URLs; an unconfigured provider refuses consent.
`/openapi.json` is the API contract. No app is configured by default.

## Reviewed deployment access (console only)

There is no public enrollment, wildcard bypass or HTTP key-management endpoint.
Access is managed from the server terminal; ownership of the host is administrative
access. Requests use `X-AgenticOS-Bridge-Key` on metadata, start, exchange and refresh.
The browser callback uses its authenticated encrypted ticket, bound to the enrollment;
no deployment key appears in a browser URL. Every operation checks current revocation,
expiry and provider permission. Starts and metadata also check the exact enrolled origin.
A key is a bearer credential: keep it secret. Origin binding restricts callbacks but
cannot prove a caller physically runs on that host.

Prepare the private registry once (container UID 65532):

```sh
sudo install -d -m 700 -o 65532 -g 65532 /opt/agenticos-bridge/access
docker compose -p agenticos-bridge -f compose.production.yml run --rm --no-deps \
  --entrypoint /app/.venv/bin/python bridge -m agenticos_bridge.cli init
```

After reviewing the organization, domain control, use case, provider rules, incident
contact and applicable agreements, issue a time-limited key:

```sh
umask 077
docker compose -p agenticos-bridge -f compose.production.yml exec -T bridge \
  /app/.venv/bin/python -m agenticos_bridge.cli issue \
  --origin https://agents.example.com --contact security@example.com \
  --agreement-reference internal-approved-review-id --provider google --provider microsoft \
  --days 90 > /secure/location/deployment-key.json
```

Use an existing protected directory for that output. The secret is returned **once**;
`list` never returns it or its hash. Deliver it through an agreed secure channel,
not a public issue or ordinary email. The registry stores SHA-256 of a random
256-bit secret, an enrollment ID, exact origin, contact, agreement reference,
providers, issue/expiry timestamps and optional revocation timestamp. It contains
no account access/refresh tokens or work content. CLI expiry defaults to 90 days
and is limited to 1–365 days. Approval is an operator decision, not an automated
claim that the service has passed legal or provider review.

```sh
docker compose -p agenticos-bridge -f compose.production.yml exec -T bridge \
  /app/.venv/bin/python -m agenticos_bridge.cli list
docker compose -p agenticos-bridge -f compose.production.yml exec -T bridge \
  /app/.venv/bin/python -m agenticos_bridge.cli revoke ENROLLMENT_ID
```

Revocation applies to subsequent bridge operations without restarting. It cannot
cancel in-flight provider requests, retract previously issued access tokens or revoke
the provider grant. Revoke at the provider too after compromise. A new key creates
a new enrollment; existing managed accounts must reconnect. Back up the registry
with SQLite's backup interface into encrypted, access-controlled storage and preserve
revocations on restore. Restoring an old backup can re-enable revoked access; reconcile
revocations before serving traffic. There is no automatic access-record deletion;
review retention and remove records/backups under the agreed retention procedure.

**Upgrade:** `BRIDGE_ALLOWED_ORIGINS` no longer grants access. Initialize the registry
and explicitly issue keys; pre-enrollment pending flows and refresh receipts must
be replaced by reconnecting accounts. Own-credential connections are unaffected.

## Provider registration

Configure both `BRIDGE_<PROVIDER>_CLIENT_ID` and `BRIDGE_<PROVIDER>_CLIENT_SECRET`.
Register these **web** callback URLs exactly:

| Provider | Callback |
| --- | --- |
| Google | `https://bridge-agenticos.testapp.ovh/v1/oauth/callback/google` |
| Microsoft | `https://bridge-agenticos.testapp.ovh/v1/oauth/callback/microsoft` |
| Slack | `https://bridge-agenticos.testapp.ovh/v1/oauth/callback/slack` |

Google needs the Workspace APIs and the scopes listed in `src/agenticos_bridge/scopes.json`.
Sensitive/restricted permissions require Google's applicable verification; restricted
Gmail scopes may require an independent security assessment. Microsoft must permit the
intended organizations/personal accounts; tenant consent policy still applies. Slack
needs user scopes, app distribution and preferably token rotation. IMAP and Odoo use
local credentials in AgenticOS and do not pass through this broker.

Provider credentials alone do not prove production readiness. Test consent, identity,
scope refusal, refresh and revocation against each real app before public enrollment.
See the [Google OAuth guide](https://developers.google.com/identity/protocols/oauth2/web-server),
[Microsoft code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow),
and [Slack rotation guide](https://docs.slack.dev/authentication/using-token-rotation/).

## Deployment

`compose.production.yml` creates one isolated, non-root, read-only container with CPU,
memory, swap, PID and concurrency limits. It uses the existing `traefik_webgateway`
network and routes only `bridge-agenticos.testapp.ovh`. TLS terminates at Traefik;
the internal Docker hop is plaintext and belongs to the host trust boundary. For a
multi-host deployment use TLS on that hop too. Only the private deployment-access registry is mounted; no account-token volume is mounted.

Place config at `/opt/agenticos-bridge/config/bridge.env` (root-only, mode 600).
Keep the encryption key stable across restarts. Rotate it on compromise: all old
pending flows and refresh receipts become invalid and accounts must reconnect.
Receipts expire after one year; successful refresh issues a new one.

```sh
docker compose -p agenticos-bridge -f compose.production.yml up -d --build
curl --fail http://127.0.0.1:8060/healthz
```

The included router disables access logging **for this router** and adds rate and
in-flight limits. Do not add request/response-body tracing, error reporters with
locals, packet capture, core dumps or query logging on this service. Never log the
client settings. Existing TLS proxy/host administrators and the bridge process can
observe transient token material: this is a trusted broker, not end-to-end encryption
against the operator. Server app secrets and the ticket key are persistent server
configuration; user tokens are not persisted here.

## Checks

```sh
uv run pytest tests/test_oauth.py tests/test_access.py -q
uv run ruff check src tests
uv run ruff format --check src tests
uv run ty check src
```

These cover protocol/security contracts using mocked provider HTTP responses, not a
claim that real provider verification or a penetration test has been completed.


## Contributing

Read [AGENTS.md](AGENTS.md) for the architecture and development boundaries and
[SECURITY.md](SECURITY.md) for the threat model. Provider additions need official
protocol documentation, allowlisted scopes and endpoints, code/refresh contract
tests, negative proof tests and operator setup instructions. Changes to token
storage, callback trust or public enrollment are architectural changes.

Project instructions are shared by Claude Code, Codex and OpenCode through one
`AGENTS.md` and canonical task skills. See the task table in that file for provider
code, app registration and deployment. A third-party self-hosted bridge must replace
the public pages' Vstorm-specific operator and policy details before publishing.

The repository follows AgenticOS team permissions, protected main, immutable tags,
secret scanning/push protection and CodeQL security checks. Required CI jobs are
adapted to this service: lint, test, image and Security Scan. There is no Node or
frontend build toolchain; the public pages are static assets served by FastAPI.
