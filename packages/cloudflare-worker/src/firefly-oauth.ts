/**
 * Delegated OAuth against Firefly III's own Passport server.
 *
 * Firefly III users log in with their real Firefly III username and
 * password on Firefly's own /login page — this worker never sees or stores
 * a password. What comes back is a Firefly access/refresh token pair scoped
 * to that one Firefly user, which is what every subsequent Firefly III API
 * call is made with.
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

const tokenEndpoint = (baseUrl: string): string => `${baseUrl}/oauth/token`;

const asFireflyTokens = (json: FireflyTokenResponse): FireflyTokens => ({
  fireflyAccessToken: json.access_token,
  fireflyRefreshToken: json.refresh_token,
  fireflyExpiresAt: Date.now() + json.expires_in * 1000,
});

const postForm = async (url: string, body: Record<string, string>): Promise<FireflyTokenResponse> => {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams(body).toString(),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Firefly III token endpoint returned ${response.status}: ${errorText}`);
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
    throw new Error(`Firefly III /about/user returned ${response.status}`);
  }
  const json = await response.json() as { data: { id: string; attributes: { email: string } } };
  return { id: json.data.id, email: json.data.attributes.email };
};
