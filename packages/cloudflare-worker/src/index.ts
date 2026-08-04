import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { cors } from 'hono/cors'
import OAuthProvider, { OAuthError } from '@cloudflare/workers-oauth-provider'

import { FireflyIIIAgent } from './agent'
import { getMcpServerConfig } from './config'
import { exchangeFireflyCode, refreshFireflyToken, fetchFireflyIdentity, FireflyTokens } from './firefly-oauth'

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

const unauthorized = (): Response => new Response(
  JSON.stringify({ error: 'Unauthorized', message: 'No Firefly III session is associated with this token.' }),
  { status: 401, headers: { 'content-type': 'application/json' } },
)

apiApp.use('/mcp', async (c) => {
  const config = getMcpServerConfig(c.env, grantProps(c).fireflyAccessToken)
  if (!config) return unauthorized()
  // `as any`: Hono's ExecutionContext type and the ambient global one (which
  // McpAgent.serve()/serveSSE() expect) have drifted apart on fields like
  // `tracing` that neither this glue code nor the agents SDK actually reads;
  // both are the same object at runtime.
  const agentContext = { ...c.executionCtx, props: config } as any
  const mcp = await FireflyIIIAgent.serve('/mcp').fetch(c.req.raw, c.env, agentContext)
  return rewriteCorsOrigin(c.req.raw, mcp)
})

apiApp.use('/sse*', async (c) => {
  const config = getMcpServerConfig(c.env, grantProps(c).fireflyAccessToken)
  if (!config) return unauthorized()
  // `as any`: Hono's ExecutionContext type and the ambient global one (which
  // McpAgent.serve()/serveSSE() expect) have drifted apart on fields like
  // `tracing` that neither this glue code nor the agents SDK actually reads;
  // both are the same object at runtime.
  const agentContext = { ...c.executionCtx, props: config } as any
  const mcp = await FireflyIIIAgent.serveSSE('/sse').fetch(c.req.raw, c.env, agentContext)
  return rewriteCorsOrigin(c.req.raw, mcp)
})

// ---- Delegated login: Firefly III is the identity provider ----
// /authorize doesn't render a login form itself — it hands the browser off
// to Firefly III's own /oauth/authorize, which redirects to Firefly's real
// /login when there's no session. Firefly validates the username/password,
// not us; we never see either. What we get back at /callback is a Firefly
// access/refresh token pair scoped to that one Firefly user.
//
// The original MCP client's AuthRequest (oauthReqInfo) has to survive the
// round trip through Firefly, so it travels as the `state` param on the
// Firefly leg and is decoded back out of it in /callback. This mirrors
// Cloudflare's own upstream-OAuth demos (e.g. remote-mcp-github-oauth) —
// oauthReqInfo carries no secret, and Firefly only ever redirects back to
// our exact registered redirect_uri with a `code` it minted itself, so
// nothing here needs a separate CSRF nonce on top of it.

const base64UrlEncode = (obj: unknown): string =>
  btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

const base64UrlDecode = (s: string): unknown =>
  JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')))

const defaultHandler = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)

    if (url.pathname === '/authorize' && request.method === 'GET') {
      const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request)
      const fireflyAuthorizeUrl = new URL(`${env.FIREFLY_III_BASE_URL}/oauth/authorize`)
      fireflyAuthorizeUrl.searchParams.set('client_id', env.FIREFLY_OAUTH_CLIENT_ID)
      fireflyAuthorizeUrl.searchParams.set('redirect_uri', env.FIREFLY_OAUTH_REDIRECT_URI)
      fireflyAuthorizeUrl.searchParams.set('response_type', 'code')
      fireflyAuthorizeUrl.searchParams.set('scope', '')
      fireflyAuthorizeUrl.searchParams.set('state', base64UrlEncode(oauthReqInfo))
      return Response.redirect(fireflyAuthorizeUrl.toString(), 302)
    }

    if (url.pathname === '/callback' && request.method === 'GET') {
      const code = url.searchParams.get('code')
      const state = url.searchParams.get('state')
      if (!code || !state) {
        return new Response('Bad request: missing code or state', { status: 400 })
      }

      let oauthReqInfo: Awaited<ReturnType<typeof env.OAUTH_PROVIDER.parseAuthRequest>>
      try {
        oauthReqInfo = base64UrlDecode(state) as typeof oauthReqInfo
      } catch {
        return new Response('Bad request: invalid state', { status: 400 })
      }

      let tokens
      try {
        tokens = await exchangeFireflyCode(env, code)
      } catch (error) {
        console.error('Firefly III code exchange failed:', error)
        return new Response('Firefly III sign-in failed. Please try again.', { status: 502 })
      }

      let identity
      try {
        identity = await fetchFireflyIdentity(env, tokens.fireflyAccessToken)
      } catch (error) {
        console.error('Firefly III identity lookup failed:', error)
        return new Response('Firefly III sign-in failed. Please try again.', { status: 502 })
      }

      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId: identity.id,
        metadata: { label: identity.email },
        scope: oauthReqInfo.scope,
        // Decrypted back into ctx.props on every /mcp and /sse call (see
        // grantProps above), and handed to tokenExchangeCallback below
        // whenever this grant's MCP-issued access token is refreshed.
        props: tokens,
      })
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
    try {
      const refreshed = await refreshFireflyToken(env, props.fireflyRefreshToken)
      return { newProps: refreshed }
    } catch (error) {
      console.error('Firefly III token refresh failed:', error)
      throw new OAuthError('invalid_grant', { description: 'Firefly III session expired; please sign in again.' })
    }
  },
})

export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => buildProvider(env).fetch(request, env, ctx),
}

export { FireflyIIIAgent } from './agent'
