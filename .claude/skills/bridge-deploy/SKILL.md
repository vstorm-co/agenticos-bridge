---
name: bridge-deploy
description: Deploy or update the authorized AgenticOS Bridge service on its VPS, verify TLS/health, preserve server app credentials and diagnose its isolated container. Use for bridge operations, not upgrading an AgenticOS deployment beside it.
---

# Deploy the bridge

Read `README.md`, `SECURITY.md` and `compose.production.yml`. Deployment requires
user authorization for the target. Existing access to the host is not permission
to restart other applications or expose a new hostname.

Use a reviewed commit with successful lint/test/image/security and CodeQL evidence.
Release tags are immutable. Build from tracked source, with the lockfile, not a
working directory containing credential downloads or an `.env` file.

On the current service host, `vps-agenticos`, releases are under
`/opt/agenticos-bridge/releases/` and `current` points to the active release.
Configuration is `/opt/agenticos-bridge/config/bridge.env`, root-only, mode 600.
Keep the ticket key stable; replacing it invalidates pending flows and receipts.
Patch provider keys deliberately and preserve unrelated keys. Do not print config
or full Docker environments while inspecting health.

Compose uses project `agenticos-bridge` and the existing `traefik_webgateway`
network. Touch only this service. Preserve non-root, read-only filesystem, dropped
capabilities, no-new-privileges, memory/swap/PID limits and OAuth access-log exclusion.
Do not open a public raw API port; traffic uses the configured TLS router.

Verify internal health first, then public HTTPS without `-k`, provider metadata,
public policy pages and the exact source revision. A newly recreated container may
be absent from Traefik until its first successful health check; distinguish that
short readiness window from an application failure. Inspect bounded safe startup
logs, not request bodies. Keep the previous safe release available for rollback,
but never roll back to a known vulnerable dependency merely to get a green health.

Report deployed SHA, health/TLS, configured-vs-unconfigured provider status and any
verification/enrollment limitation. No successful health check proves live OAuth
consent, provider approval or an independent security audit.
