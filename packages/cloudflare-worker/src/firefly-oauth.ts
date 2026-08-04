/**
 * Delegated OAuth against Firefly III's own Passport server.
 *
 * Firefly III users log in with their real Firefly III username and
 * password on Firefly's own /login page — this worker never sees or stores
 * a password. What comes back is a Firefly access/refresh token pair scoped
 * to that one Firefly user, which is what every subsequent Firefly III API
 * call is made with.
 *
 * Deliberately a pure network client with no logging of its own - callers
 * (index.ts) wrap each call with log.ts's withStageLogging, keeping this
 * module trivial to unit test with a mocked fetch.
 */

export interface FireflyTokens {
  fireflyAccessToken: string;
  fireflyRefreshToken: string;
  /** Epoch milliseconds. */
  fireflyExpiresAt: number;
}

export interface FireflyIdentity {
  id: string;
  email: string;
}

interface FireflyTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

/** Thrown on any non-2xx response from Firefly's OAuth/identity endpoints. Never carries the raw response body - only a bounded, safe description. */
export class FireflyOAuthError extends Error {
  readonly status: number;
  constructor(status: number, safeDescription: string) {
    super(safeDescription);
    this.name = 'FireflyOAuthError';
    this.status = status;
  }
}

const tokenEndpoint = (baseUrl: string): string => `${baseUrl}/oauth/token`;

const asFireflyTokens = (json: FireflyTokenResponse): FireflyTokens => ({
  fireflyAccessToken: json.access_token,
  fireflyRefreshToken: json.refresh_token,
  fireflyExpiresAt: Date.now() + json.expires_in * 1000,
});

// Standard OAuth error response shape: { error, error_description }. Only
// ever surfaces error/error_description - never the full body, which in
// principle could echo back parts of the request.
const safeOAuthErrorDescription = (status: number, bodyText: string): string => {
  try {
    const parsed = JSON.parse(bodyText) as { error?: unknown; error_description?: unknown };
    const code = typeof parsed.error === 'string' ? parsed.error : 'unknown_error';
    const description = typeof parsed.error_description === 'string' ? parsed.error_description : undefined;
    return description ? `${code}: ${description}`.slice(0, 300) : code;
  } catch {
    return `HTTP ${status}`;
  }
};

const postForm = async (url: string, body: Record<string, string>): Promise<FireflyTokenResponse> => {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams(body).toString(),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new FireflyOAuthError(response.status, safeOAuthErrorDescription(response.status, errorText));
  }
  return await response.json();
};

/** Authorization-code leg: exchanges the code from /callback for a token pair. */
export const exchangeFireflyCode = async (env: Env, code: string): Promise<FireflyTokens> => {
  const json = await postForm(tokenEndpoint(env.FIREFLY_III_BASE_URL), {
    grant_type: 'authorization_code',
    client_id: env.FIREFLY_OAUTH_CLIENT_ID,
    client_secret: env.FIREFLY_OAUTH_CLIENT_SECRET,
    redirect_uri: env.FIREFLY_OAUTH_REDIRECT_URI,
    code,
  });
  return asFireflyTokens(json);
};

/** Refresh leg: called from tokenExchangeCallback (see index.ts) when this grant's MCP access token is refreshed. */
export const refreshFireflyToken = async (env: Env, refreshToken: string): Promise<FireflyTokens> => {
  const json = await postForm(tokenEndpoint(env.FIREFLY_III_BASE_URL), {
    grant_type: 'refresh_token',
    client_id: env.FIREFLY_OAUTH_CLIENT_ID,
    client_secret: env.FIREFLY_OAUTH_CLIENT_SECRET,
    refresh_token: refreshToken,
  });
  return asFireflyTokens(json);
};

/** Identifies which Firefly user a freshly-issued access token belongs to, for the OAuth grant's userId/label. */
export const fetchFireflyIdentity = async (env: Env, accessToken: string): Promise<FireflyIdentity> => {
  const response = await fetch(`${env.FIREFLY_III_BASE_URL}/api/v1/about/user`, {
    headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new FireflyOAuthError(response.status, safeOAuthErrorDescription(response.status, errorText));
  }
  const json = await response.json() as { data: { id: string; attributes: { email: string } } };
  return { id: json.data.id, email: json.data.attributes.email };
};
