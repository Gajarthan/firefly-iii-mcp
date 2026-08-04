import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { exchangeFireflyCode, refreshFireflyToken, fetchFireflyIdentity, FireflyOAuthError } from './firefly-oauth';

const FAKE_ENV = {
  FIREFLY_III_BASE_URL: 'https://fin.example.test',
  FIREFLY_OAUTH_CLIENT_ID: 'client-id',
  FIREFLY_OAUTH_CLIENT_SECRET: 'client-secret',
  FIREFLY_OAUTH_REDIRECT_URI: 'https://worker.example.test/callback',
} as unknown as Env;

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = globalThis.fetch; });
afterEach(() => { globalThis.fetch = originalFetch; });

describe('exchangeFireflyCode', () => {
  test('success: returns a token pair derived from the token endpoint response', async () => {
    globalThis.fetch = mock(async () => jsonResponse({
      access_token: 'firefly-access-1', refresh_token: 'firefly-refresh-1', expires_in: 3600, token_type: 'Bearer',
    })) as unknown as typeof fetch;

    const tokens = await exchangeFireflyCode(FAKE_ENV, 'auth-code-123');
    expect(tokens.fireflyAccessToken).toBe('firefly-access-1');
    expect(tokens.fireflyRefreshToken).toBe('firefly-refresh-1');
    expect(tokens.fireflyExpiresAt).toBeGreaterThan(Date.now());
  });

  test('success: sends the code, client credentials, and redirect_uri as form-encoded body', async () => {
    let capturedBody: string | undefined;
    globalThis.fetch = mock(async (_url: string, init?: RequestInit) => {
      capturedBody = init?.body as string;
      return jsonResponse({ access_token: 'a', refresh_token: 'r', expires_in: 60, token_type: 'Bearer' });
    }) as unknown as typeof fetch;

    await exchangeFireflyCode(FAKE_ENV, 'auth-code-xyz');
    const params = new URLSearchParams(capturedBody);
    expect(params.get('grant_type')).toBe('authorization_code');
    expect(params.get('code')).toBe('auth-code-xyz');
    expect(params.get('client_id')).toBe('client-id');
    expect(params.get('client_secret')).toBe('client-secret');
    expect(params.get('redirect_uri')).toBe('https://worker.example.test/callback');
  });

  test('failure: a non-2xx response throws FireflyOAuthError without leaking the raw body', async () => {
    globalThis.fetch = mock(async () => new Response(
      JSON.stringify({ error: 'invalid_grant', error_description: 'The authorization code is invalid or expired.' }),
      { status: 400, headers: { 'content-type': 'application/json' } },
    )) as unknown as typeof fetch;

    await expect(exchangeFireflyCode(FAKE_ENV, 'bad-code')).rejects.toThrow(FireflyOAuthError);
    try {
      await exchangeFireflyCode(FAKE_ENV, 'bad-code');
    } catch (error) {
      expect(error).toBeInstanceOf(FireflyOAuthError);
      expect((error as FireflyOAuthError).status).toBe(400);
      expect((error as FireflyOAuthError).message).toContain('invalid_grant');
    }
  });
});

describe('refreshFireflyToken', () => {
  test('success: rotation - returns a new access/refresh token pair distinct from the input', async () => {
    globalThis.fetch = mock(async () => jsonResponse({
      access_token: 'rotated-access', refresh_token: 'rotated-refresh', expires_in: 3600, token_type: 'Bearer',
    })) as unknown as typeof fetch;

    const refreshed = await refreshFireflyToken(FAKE_ENV, 'old-refresh-token');
    expect(refreshed.fireflyAccessToken).toBe('rotated-access');
    expect(refreshed.fireflyRefreshToken).toBe('rotated-refresh');
    expect(refreshed.fireflyRefreshToken).not.toBe('old-refresh-token');
  });

  test('failure: an invalid refresh token surfaces as FireflyOAuthError with status', async () => {
    globalThis.fetch = mock(async () => new Response(
      JSON.stringify({ error: 'invalid_grant', error_description: 'refresh token is invalid' }),
      { status: 400, headers: { 'content-type': 'application/json' } },
    )) as unknown as typeof fetch;

    await expect(refreshFireflyToken(FAKE_ENV, 'expired-refresh-token')).rejects.toThrow(FireflyOAuthError);
  });
});

describe('fetchFireflyIdentity', () => {
  test('success: returns the Firefly user id and email', async () => {
    globalThis.fetch = mock(async () => jsonResponse({
      data: { id: '1', attributes: { email: 'gajarthan@bohar.lk' } },
    })) as unknown as typeof fetch;

    const identity = await fetchFireflyIdentity(FAKE_ENV, 'some-access-token');
    expect(identity.id).toBe('1');
    expect(identity.email).toBe('gajarthan@bohar.lk');
  });

  test('success: two different users produce two different identities from the same call shape', async () => {
    globalThis.fetch = mock(async () => jsonResponse({
      data: { id: '2', attributes: { email: 'gowshika@gmail.com' } },
    })) as unknown as typeof fetch;

    const identity = await fetchFireflyIdentity(FAKE_ENV, 'a-different-access-token');
    expect(identity.id).toBe('2');
    expect(identity.email).toBe('gowshika@gmail.com');
  });

  test('failure: a 401 from /about/user throws FireflyOAuthError', async () => {
    globalThis.fetch = mock(async () => new Response('Unauthorized', { status: 401 })) as unknown as typeof fetch;
    await expect(fetchFireflyIdentity(FAKE_ENV, 'bad-token')).rejects.toThrow(FireflyOAuthError);
  });

  test('sends the access token as a Bearer Authorization header', async () => {
    const captured: { auth: string | null } = { auth: null };
    globalThis.fetch = mock(async (_url: string, init?: RequestInit) => {
      captured.auth = (init?.headers as Record<string, string>)?.authorization ?? null;
      return jsonResponse({ data: { id: '1', attributes: { email: 'x@example.com' } } });
    }) as unknown as typeof fetch;

    await fetchFireflyIdentity(FAKE_ENV, 'the-secret-access-token');
    expect(captured.auth).toBe('Bearer the-secret-access-token');
  });
});
