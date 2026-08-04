import { Hono, Context } from 'hono'
import { logger } from 'hono/logger'
import { cors } from 'hono/cors'
import OAuthProvider, { OAuthError } from '@cloudflare/workers-oauth-provider'

import { FireflyIIIAgent } from './agent'
import { getMcpServerConfig } from './config'
import { exchangeFireflyCode, refreshFireflyToken, fetchFireflyIdentity, FireflyTokens, FireflyOAuthError } from './firefly-oauth'
import { signState, verifyStateStructure, consumeStateNonce } from './state'
import { newCorrelationId, hashId, logEvent } from './log'
import { GIT_COMMIT, BUILD_TIME } from './build-info'

// Requests from browser-based MCP clients (claude.ai, ChatGPT) are the only
// ones CORS is relevant to at all — non-browser callers ignore it entirely.
const ALLOWED_ORIGINS = [
  'https://claude.ai',
  'https://claude.com',
  'https://chatgpt.com',
  'https://chat.openai.com',
]

// agents@0.0.94's McpAgent.serve()/serveSSE() hardcode
// `Access-Control-Allow-Origin: "*"` internally whenever no corsOptions is
// passed (see node_modules/agents/dist/mcp/index.js), and only ever accept a
// single literal string there — not an allowlist. This rewrites whatever
// the library set, after the fact, on every response those two routes
// return, restricting it to ALLOWED_ORIGINS.
const rewriteCorsOrigin = (req: Request, res: Response): Response => {
  const requestOrigin = req.headers.get('origin')
  if (requestOrigin && ALLOWED_ORIGINS.includes(requestOrigin)) {
    res.headers.set('Access-Control-Allow-Origin', requestOrigin)
    res.headers.append('Vary', 'Origin')
  } else {
    res.headers.delete('Access-Control-Allow-Origin')
  }
  return res
}

const jsonError = (status: number, code: string, message: string): Response => new Response(
  JSON.stringify({ code, message, retryable: false }),
  { status, headers: { 'content-type': 'application/json' } },
)

// ---- Protected MCP app ----
// OAuthProvider (below) only ever invokes this once it has verified the
// request carries a valid access token issued through our own /authorize →
// Firefly III login. There is no other way to reach these routes, which is
// what makes it safe for getMcpServerConfig() to use the decrypted grant's
// Firefly access token unconditionally.
const apiApp = new Hono<{ Bindings: Env }>()
apiApp.use(logger())
apiApp.use('*', cors({ origin: ALLOWED_ORIGINS }))

// OAuthProvider decrypts the grant created at /callback time and sets it as
// `ctx.props` before invoking this handler (see node_modules/@cloudflare/
// workers-oauth-provider dist/oauth-provider.js, decryptProps call). Not to
// be confused with the second `props` assigned below, which is McpAgent's
// own concept: the config handed to the Durable Object instance.
const grantProps = (c: { executionCtx: unknown }): Partial<FireflyTokens> =>
  (c.executionCtx as { props?: Partial<FireflyTokens> } | undefined)?.props ?? {}

const handleMcpRoute = (transport: 'mcp' | 'sse') => async (c: Context<{ Bindings: Env }>) => {
  const correlationId = newCorrelationId()
  const props = grantProps(c)
  const config = getMcpServerConfig(c.env, props.fireflyAccessToken)
  if (!config) {
    logEvent({ correlationId, stage: 'mcp_connection', result: 'failure', errorCode: 'AUTHENTICATION_REQUIRED' })
    return jsonError(401, 'AUTHENTICATION_REQUIRED', 'No Firefly III session is associated with this token.')
  }

  const fireflyUserIdHash = props.fireflyAccessToken ? await hashId(props.fireflyAccessToken) : undefined
  // Binds tool_invocation/firefly_api_response log lines from inside core's
  // executeApiTool back to this request's correlationId, without core ever
  // needing to know what a correlationId is - see McpServerConfig.logger.
  const configWithLogger = {
    ...config,
    logger: (event: Parameters<NonNullable<typeof config.logger>>[0]) =>
      logEvent({ correlationId, fireflyUserIdHash, ...event }),
  }

  // `as any`: Hono's ExecutionContext type and the ambient global one (which
  // McpAgent.serve()/serveSSE() expect) have drifted apart on fields like
  // `tracing` that neither this glue code nor the agents SDK actually reads;
  // both are the same object at runtime.
  const agentContext = { ...c.executionCtx, props: configWithLogger } as any
  const start = Date.now()
  const mcp = transport === 'mcp'
    ? await FireflyIIIAgent.serve('/mcp').fetch(c.req.raw, c.env, agentContext)
    : await FireflyIIIAgent.serveSSE('/sse').fetch(c.req.raw, c.env, agentContext)
  logEvent({
    correlationId, fireflyUserIdHash, stage: 'mcp_connection',
    durationMs: Date.now() - start, result: mcp.ok ? 'success' : 'failure',
  })
  return rewriteCorsOrigin(c.req.raw, mcp)
}

apiApp.use('/mcp', handleMcpRoute('mcp'))
apiApp.use('/sse*', handleMcpRoute('sse'))

// ---- Delegated login: Firefly III is the identity provider ----
// /authorize doesn't render a login form itself — it hands the browser off
// to Firefly III's own /oauth/authorize, which redirects to Firefly's real
// /login when there's no session. Firefly validates the username/password,
// not us; we never see either. What we get back at /callback is a Firefly
// access/refresh token pair scoped to that one Firefly user.
//
// The original MCP client's AuthRequest (oauthReqInfo) has to survive the
// round trip through Firefly, so it travels as a signed, expiring, single-
// use `state` param on the Firefly leg and is verified + decoded back out
// of it in /callback — see state.ts.

const defaultHandler = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)
    const correlationId = newCorrelationId()

    if (url.pathname === '/health' && request.method === 'GET') {
      return new Response(JSON.stringify({ status: 'ok' }), { headers: { 'content-type': 'application/json' } })
    }

    if (url.pathname === '/version' && request.method === 'GET') {
      return new Response(JSON.stringify({
        service: 'gajarthan-finance-mcp',
        git_commit: GIT_COMMIT,
        build_time: BUILD_TIME,
        environment: env.ENVIRONMENT ?? 'unknown',
      }), { headers: { 'content-type': 'application/json' } })
    }

    if (url.pathname === '/authorize' && request.method === 'GET') {
      const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request)
      const state = await signState(env.MCP_STATE_SIGNING_KEY, oauthReqInfo, env.FIREFLY_OAUTH_REDIRECT_URI)

      const fireflyAuthorizeUrl = new URL(`${env.FIREFLY_III_BASE_URL}/oauth/authorize`)
      fireflyAuthorizeUrl.searchParams.set('client_id', env.FIREFLY_OAUTH_CLIENT_ID)
      fireflyAuthorizeUrl.searchParams.set('redirect_uri', env.FIREFLY_OAUTH_REDIRECT_URI)
      fireflyAuthorizeUrl.searchParams.set('response_type', 'code')
      fireflyAuthorizeUrl.searchParams.set('scope', '')
      fireflyAuthorizeUrl.searchParams.set('state', state)

      logEvent({ correlationId, stage: 'authorize', result: 'success' })
      return Response.redirect(fireflyAuthorizeUrl.toString(), 302)
    }

    if (url.pathname === '/callback' && request.method === 'GET') {
      const code = url.searchParams.get('code')
      const state = url.searchParams.get('state')
      if (!code || !state) {
        logEvent({ correlationId, stage: 'callback', result: 'failure', errorCode: 'AUTHORIZATION_FAILED' })
        return jsonError(400, 'AUTHORIZATION_FAILED', 'Missing code or state.')
      }

      const validation = await verifyStateStructure(env.MCP_STATE_SIGNING_KEY, state, env.FIREFLY_OAUTH_REDIRECT_URI)
      if (!validation.ok) {
        logEvent({ correlationId, stage: 'callback', result: 'failure', errorCode: `AUTHORIZATION_FAILED:${validation.error}` })
        return jsonError(400, 'AUTHORIZATION_FAILED', 'The sign-in link is invalid or has expired. Please try connecting again.')
      }
      const { payload } = validation
      const remainingTtl = payload.exp - Math.floor(Date.now() / 1000)
      const nonceOk = await consumeStateNonce(env.OAUTH_KV, payload.nonce, remainingTtl)
      if (!nonceOk) {
        logEvent({ correlationId, stage: 'callback', result: 'failure', errorCode: 'AUTHORIZATION_FAILED:replayed' })
        return jsonError(400, 'AUTHORIZATION_FAILED', 'This sign-in link has already been used. Please try connecting again.')
      }
      const oauthReqInfo = payload.request as Awaited<ReturnType<typeof env.OAUTH_PROVIDER.parseAuthRequest>>

      let tokens: FireflyTokens
      try {
        tokens = await exchangeFireflyCode(env, code)
        logEvent({ correlationId, stage: 'token_exchange', result: 'success' })
      } catch (error) {
        const status = error instanceof FireflyOAuthError ? error.status : undefined
        logEvent({ correlationId, stage: 'token_exchange', result: 'failure', upstreamStatus: status, errorCode: 'AUTHORIZATION_FAILED' })
        return jsonError(502, 'AUTHORIZATION_FAILED', 'Firefly III sign-in failed. Please try again.')
      }

      let identity
      try {
        identity = await fetchFireflyIdentity(env, tokens.fireflyAccessToken)
        logEvent({ correlationId, stage: 'identity_lookup', result: 'success', fireflyUserIdHash: await hashId(identity.id) })
      } catch (error) {
        const status = error instanceof FireflyOAuthError ? error.status : undefined
        logEvent({ correlationId, stage: 'identity_lookup', result: 'failure', upstreamStatus: status, errorCode: 'AUTHORIZATION_FAILED' })
        return jsonError(502, 'AUTHORIZATION_FAILED', 'Firefly III sign-in failed. Please try again.')
      }

      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId: identity.id,
        metadata: { label: identity.email },
        scope: oauthReqInfo.scope,
        // Decrypted back into ctx.props on every /mcp and /sse call (see
        // grantProps above), and handed to tokenExchangeCallback below
        // whenever this grant's MCP-issued access token is refreshed. Two
        // different Firefly users (different userId here) always get
        // separate grants with separate encrypted props - one user's tokens
        // are never reachable from another's session.
        props: tokens,
      })
      logEvent({ correlationId, stage: 'grant_creation', result: 'success', fireflyUserIdHash: await hashId(identity.id) })
      return Response.redirect(redirectTo, 302)
    }

    return new Response('Not found', { status: 404 })
  },
}

// OAuthProviderOptions has no way to hand tokenExchangeCallback the Worker's
// `env` (it only receives grantType/props/etc, see TokenExchangeCallbackOptions
// in node_modules/@cloudflare/workers-oauth-provider/dist/oauth-provider.d.ts) —
// so the provider is built fresh per request, inside fetch(), where `env` is
// actually in scope, rather than once at module load. The constructor itself
// is just plain option storage (no I/O), so this costs nothing per request.
const buildProvider = (env: Env) => new OAuthProvider({
  apiRoute: ['/mcp', '/sse'],
  apiHandler: apiApp,
  defaultHandler,
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/token',
  clientRegistrationEndpoint: '/register',
  scopesSupported: ['mcp'],
  // Keeps the Firefly token pair fresh whenever an MCP client (Claude,
  // ChatGPT) refreshes its own access token against our /token endpoint —
  // that refresh cadence is what drives Firefly token refresh too, so there
  // is no separate timer or background job.
  tokenExchangeCallback: async (options) => {
    if (options.grantType !== 'refresh_token') return
    const props = options.props as Partial<FireflyTokens>
    if (!props.fireflyRefreshToken) return
    // Firefly access tokens are long-lived by default; skip the upstream
    // round-trip unless this one is actually close to expiring.
    if (props.fireflyExpiresAt && props.fireflyExpiresAt - Date.now() > 5 * 60 * 1000) return
    const correlationId = newCorrelationId()
    try {
      const refreshed = await refreshFireflyToken(env, props.fireflyRefreshToken)
      logEvent({ correlationId, stage: 'token_refresh', result: 'success' })
      return { newProps: refreshed }
    } catch (error) {
      const status = error instanceof FireflyOAuthError ? error.status : undefined
      logEvent({ correlationId, stage: 'token_refresh', result: 'failure', upstreamStatus: status, errorCode: 'TOKEN_REFRESH_FAILED' })
      throw new OAuthError('invalid_grant', { description: 'Firefly III session expired; please sign in again.' })
    }
  },
})

export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => buildProvider(env).fetch(request, env, ctx),
}

export { FireflyIIIAgent } from './agent'
