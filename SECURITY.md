# Security

This document describes the security model of this fork's actual production deployment:
`packages/cloudflare-worker`, live at `https://firefly-iii-mcp.thisanthan02.workers.dev`, talking to
`https://fin.bohar.online`. It does not describe `packages/server` or `packages/local` - see the status
notice at the top of each of those packages' READMEs.

## Authentication

The Worker does not store Firefly passwords, personal access tokens, or shared static credentials. It stores
encrypted, per-user OAuth access and refresh tokens as part of authorized MCP grants. These tokens are scoped,
revocable, and refreshed through Firefly III.

Concretely: login is delegated entirely to Firefly III's own OAuth server (Laravel Passport). When an MCP client
(Claude, ChatGPT, or anything else) connects, the Worker's `/authorize` redirects the browser to Firefly III's
`/oauth/authorize`, which redirects to Firefly's real `/login` when there's no session. The user enters their
actual Firefly III username and password on Firefly's own page - this Worker never sees, receives, or stores
either. Firefly redirects back to `/callback` with an authorization code; the Worker exchanges that for a Firefly
access/refresh token pair scoped to exactly that one Firefly user, and identifies which user via
`GET /api/v1/about/user`.

Two different Firefly III accounts (e.g. two family members sharing one Firefly III instance) each get their own
independent MCP login and independent Firefly token pair. There is no cross-account data path: which account's
data a session can reach is determined entirely by which Firefly III user actually authenticated, not by
anything this Worker's own code decides.

## OAuth token storage and encryption

The Firefly access/refresh token pair for a session is stored as the `props` of an OAuth grant managed by
[`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider), which encrypts
grant props before persisting them to the `OAUTH_KV` KV namespace and decrypts them per-request before handing
them to this Worker's own code (`ctx.props` in `packages/cloudflare-worker/src/index.ts`). This Worker never
writes a Firefly token to KV, a log line, or anywhere else in plaintext itself - encryption-at-rest for grant
storage is the OAuth provider library's responsibility, not code in this repository.

## Session expiry and refresh

- The MCP-issued access token a client (Claude/ChatGPT) holds has its own TTL, managed by
  `@cloudflare/workers-oauth-provider` (default 1 hour).
- Firefly III's own access tokens are long-lived by default (Passport's default TTL, not shortened by this
  deployment - see `app/Providers/AuthServiceProvider.php` on `fin.bohar.online`, where
  `Passport::tokensExpireIn(...)` is commented out).
- Whenever the MCP client refreshes its own access token, `tokenExchangeCallback` in `index.ts` checks whether
  the stored Firefly access token is within 5 minutes of expiry, and if so, refreshes it against Firefly's
  `/oauth/token` before returning. This is the only place Firefly token refresh happens - there is no separate
  timer or background job.
- If the Firefly refresh itself fails (e.g. the user revoked the app on Firefly's side, or the refresh token
  expired), `tokenExchangeCallback` throws `OAuthError('invalid_grant', ...)`, which forces the MCP client back
  through a fresh `/authorize` login rather than continuing on a stale or invalid token.

## Revocation

Revoking access happens on Firefly III's side, not this Worker's: removing or regenerating the "Firefly III MCP"
OAuth client's authorization for a user (Firefly III's own OAuth client management UI, under a user's Profile)
invalidates that user's Firefly refresh token, which surfaces here as a `TOKEN_REFRESH_FAILED` /
`invalid_grant` on the next refresh attempt and forces re-login. There is currently no separate "kill this MCP
session immediately, before its next token refresh" control on the Worker side - session termination is
bounded by the MCP client's own access-token TTL (up to ~1 hour), not instant. Treat this as a known limitation,
not a documented feature.

## State protection (OAuth `state` param)

The MCP client's original authorization request has to survive the round trip through Firefly III's login page,
carried in the OAuth `state` parameter (`packages/cloudflare-worker/src/state.ts`). This is not a bare
base64-encoded value - it's:

- Signed with HMAC-SHA256, keyed by the `MCP_STATE_SIGNING_KEY` secret. Any tampering with the payload
  invalidates the signature.
- Time-bound: a 10-minute expiry (`iat`/`exp` in the signed payload), checked on every `/callback`.
- Bound to the exact client (`clientId`) and redirect URI (`redirectHash`, a SHA-256 of
  `FIREFLY_OAUTH_REDIRECT_URI`) it was minted for.
- Single-use: each state carries a random nonce, recorded in `OAUTH_KV` on first successful use
  (`consumeStateNonce`). A second `/callback` attempt with the same state is rejected as a replay.

**Consistency guarantee for nonce replay protection**: Cloudflare KV is eventually consistent - writes typically
propagate across Cloudflare's edge within seconds, but this is not a hard, documented upper bound, and two
`/callback` requests for the *same* state landing on different edge colocations within that propagation window
could theoretically both observe "not yet consumed." This is accepted as a residual risk for a personal,
two-user deployment: exploiting it requires an attacker to have already captured a valid, unexpired, correctly
HMAC-signed state token, at which point replay is a narrow refinement on an already-serious compromise. A
stronger guarantee (single global consistency point for nonce consumption) would require a Durable Object
instead of KV; not implemented here as of this writing.

## Tool presets and administrative-tool policy

All 219 tools generated from the Firefly III OpenAPI spec are classified into a risk tier
(`packages/core/src/tool-risk.ts`, generated by `packages/core/scripts/generate-tool-risk.ts`):

| Tier | What it covers | Enabled by |
|---|---|---|
| `safe` | Read accounts/transactions/categories/budgets/tags, search, reports, create/update ordinary transactions, create categories/tags | `MCP_TOOL_PRESET=safe` (the default) |
| `advanced` | Everything in `safe`, plus deleting ordinary transactions and full management of bills, budgets, piggy banks, recurring transactions, attachments, and rules | `MCP_TOOL_PRESET=advanced` |
| `administrative` | `destroy_data`, `purge_data`, `bulk_update_transactions`, user/user-group management, webhook management, currency administration, system configuration, `get_cron`, and similar system-wide or irreversible operations | `MCP_ENABLE_ADMIN_TOOLS=true` **and** each tool named explicitly in `MCP_ADMIN_TOOL_ALLOWLIST` - the flag alone enables nothing |

A tool the classifier has never seen (e.g. a new one appearing after `npm run toolgen` picks up a newer Firefly
III spec, before someone re-runs `npm run toolriskgen` and reviews the result) defaults to `administrative` -
the most restrictive tier - so it can never reach the `safe` or `advanced` preset by accident.

This is enforced identically at both tool discovery (`ListTools`) and tool invocation (`CallTool`) in
`packages/core/src/server.ts` - a client that already knows (from a prior session, documentation, or a guess) the
name of a tool absent from the active preset gets a `TOOL_DISABLED` error, not a silently-executed call. Prior to
this hardening pass, only `ListTools` consulted the filter, so a disabled tool's name alone was enough to invoke
it; this was fixed as part of the same change that added tool-risk presets (see `server.test.ts`).

## Incident response

If a Firefly III account's credentials are believed compromised:
1. Change the Firefly III password for that account immediately (on `fin.bohar.online`, not this Worker).
2. Revoke the "Firefly III MCP" OAuth client's authorization for that user from Firefly III's Profile > OAuth
   page - this invalidates the stored refresh token.
3. If the compromise might extend to this Worker's own infrastructure (not just one user's Firefly password),
   rotate `MCP_STATE_SIGNING_KEY` and `FIREFLY_OAUTH_CLIENT_SECRET` (see below) and redeploy.

If the Worker's own signing key or OAuth client secret is believed compromised, rotating them (below) invalidates
all in-flight login attempts and requires every MCP client to reconnect, but does not itself invalidate already-
issued Firefly access/refresh token pairs held in existing grants - those are only revocable from Firefly III's
side (step 2 above), per account.

## Secret rotation

| Secret | Where | Rotate with | Effect of rotation |
|---|---|---|---|
| `FIREFLY_OAUTH_CLIENT_SECRET` | Cloudflare Worker secret | Regenerate the client secret in Firefly III's OAuth client admin, then `wrangler secret put FIREFLY_OAUTH_CLIENT_SECRET` | New logins work once redeployed; does not affect already-issued Firefly tokens for existing sessions |
| `MCP_STATE_SIGNING_KEY` | Cloudflare Worker secret | `openssl rand -hex 32`, then `wrangler secret put MCP_STATE_SIGNING_KEY` | Invalidates any `state` token minted before rotation and not yet consumed (at most a ~10 minute window of in-flight logins) |

Neither secret is a Firefly III user credential - rotating either never requires a user to change their Firefly
III password.

## Structured logging

Every request through the OAuth/tool-call pipeline is logged as JSON (`packages/cloudflare-worker/src/log.ts`)
with a correlation ID threaded through `authorize` -> `callback` -> `token_exchange` -> `identity_lookup` ->
`grant_creation` -> `token_refresh` -> `mcp_connection` -> `tool_invocation` -> `firefly_api_response`. Session,
grant, and Firefly user identifiers are hashed (SHA-256, truncated) before logging, never logged raw. Access
tokens, refresh tokens, authorization codes, client secrets, `Authorization` headers, passwords, and full
request/response payloads are never passed into the logger's fields in the first place, and `logEvent` also
redacts a fixed list of forbidden key names defensively, in case one ever is (`log.test.ts` asserts this).

## Reporting a vulnerability

This is a small, personally-operated deployment, not a project with a public disclosure program. If you find a
security issue in this fork, open an issue or contact the repository owner directly rather than a public PR
containing exploit details.
