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
credentials and bypass this service completely. The service includes small public information, privacy, terms and support pages for provider verification. There is no account dashboard, database, account directory, business API proxy or user-token storage here.

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

`BRIDGE_ALLOWED_ORIGINS` is a JSON list of exact AgenticOS origins, e.g.
`["https://agents.example.com","http://localhost:3000"]`. Empty means closed.
An explicit `["*"]` opens enrollment to all valid HTTPS AgenticOS callbacks (and
loopback development callbacks). This permits untrusted deployments to use the shared
provider app: enable it only after provider distribution/verification and abuse review.
The bridge never fetches a caller's callback URL. Callback paths are fixed and URLs
with userinfo, query strings, fragments or control characters are refused.

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
multi-host deployment use TLS on that hop too. No user-data volume is mounted.

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
uv run pytest tests/test_oauth.py -q
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

The repository follows AgenticOS team permissions, protected main, immutable tags,
secret scanning/push protection and CodeQL security checks. Required CI jobs are
adapted to this service: lint, test, image and Security Scan. There is no Node or
frontend build toolchain; the public pages are static assets served by FastAPI.
