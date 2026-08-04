import { describe, test, expect } from 'bun:test';
import { signState, verifyStateStructure, consumeStateNonce } from './state';

const SIGNING_KEY = 'test-signing-key-do-not-use-in-prod';
const REDIRECT_URI = 'https://firefly-iii-mcp.example.workers.dev/callback';
const OTHER_REDIRECT_URI = 'https://attacker.example.com/callback';
const REQ_INFO = { clientId: 'client-123', redirectUri: 'https://example.com/cb', scope: ['mcp'], responseType: 'code' };

// Minimal in-memory KV stand-in for consumeStateNonce's replay-tracking calls.
class FakeKV {
  store = new Map<string, string>();
  async get(key: string) { return this.store.has(key) ? this.store.get(key)! : null; }
  async put(key: string, value: string, _opts?: { expirationTtl?: number }) { this.store.set(key, value); }
}

describe('state: sign/verify round trip', () => {
  test('a freshly signed state verifies successfully', async () => {
    const state = await signState(SIGNING_KEY, REQ_INFO, REDIRECT_URI);
    const result = await verifyStateStructure(SIGNING_KEY, state, REDIRECT_URI);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.payload.clientId).toBe(REQ_INFO.clientId);
      expect((result.payload.request as typeof REQ_INFO).clientId).toBe(REQ_INFO.clientId);
    }
  });

  test('two states minted for the same request get different nonces', async () => {
    const a = await signState(SIGNING_KEY, REQ_INFO, REDIRECT_URI);
    const b = await signState(SIGNING_KEY, REQ_INFO, REDIRECT_URI);
    expect(a).not.toBe(b);
  });
});

describe('state: tamper rejection', () => {
  test('flipping a character in the signature invalidates it without changing the payload', async () => {
    const state = await signState(SIGNING_KEY, REQ_INFO, REDIRECT_URI);
    const [payloadPart, sigPart] = state.split('.');
    const tamperedChar = sigPart[5] === 'A' ? 'B' : 'A';
    const tampered = `${payloadPart}.${sigPart.slice(0, 5)}${tamperedChar}${sigPart.slice(6)}`;
    const result = await verifyStateStructure(SIGNING_KEY, tampered, REDIRECT_URI);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('bad_signature');
  });

  test('flipping a character in the payload is rejected (either as malformed or a signature mismatch)', async () => {
    const state = await signState(SIGNING_KEY, REQ_INFO, REDIRECT_URI);
    const [payloadPart, sigPart] = state.split('.');
    const tamperedChar = payloadPart[5] === 'A' ? 'B' : 'A';
    const tampered = `${payloadPart.slice(0, 5)}${tamperedChar}${payloadPart.slice(6)}.${sigPart}`;
    const result = await verifyStateStructure(SIGNING_KEY, tampered, REDIRECT_URI);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(['malformed', 'bad_signature']).toContain(result.error);
  });

  test('a state signed with a different key is rejected', async () => {
    const state = await signState('a-completely-different-key', REQ_INFO, REDIRECT_URI);
    const result = await verifyStateStructure(SIGNING_KEY, state, REDIRECT_URI);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('bad_signature');
  });

  test('malformed state (not two dot-separated parts) is rejected', async () => {
    const result = await verifyStateStructure(SIGNING_KEY, 'not-a-valid-state-token', REDIRECT_URI);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('malformed');
  });

  test('missing state is rejected as malformed', async () => {
    const result = await verifyStateStructure(SIGNING_KEY, '', REDIRECT_URI);
    expect(result.ok).toBe(false);
  });
});

describe('state: expiry', () => {
  test('a state minted with a past expiry is rejected', async () => {
    // signState always mints exp = now + 10min, so simulate expiry by
    // constructing a payload directly with an already-past exp and signing
    // it the same way signState does, rather than waiting 10 real minutes.
    const past = Math.floor(Date.now() / 1000) - 1;
    const payload = {
      request: REQ_INFO, iat: past - 600, exp: past, nonce: 'fixed-nonce-for-test',
      clientId: REQ_INFO.clientId, redirectHash: await sha256Hex(REDIRECT_URI),
    };
    const state = await signPayload(SIGNING_KEY, payload);
    const result = await verifyStateStructure(SIGNING_KEY, state, REDIRECT_URI);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('expired');
  });
});

describe('state: redirect URI binding', () => {
  test('verifying against a different redirect URI than it was minted for is rejected', async () => {
    const state = await signState(SIGNING_KEY, REQ_INFO, REDIRECT_URI);
    const result = await verifyStateStructure(SIGNING_KEY, state, OTHER_REDIRECT_URI);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('redirect_mismatch');
  });
});

describe('state: client mismatch', () => {
  test('a payload whose request.clientId disagrees with its own clientId field is rejected', async () => {
    const past = Math.floor(Date.now() / 1000);
    const payload = {
      request: { ...REQ_INFO, clientId: 'a-different-client' },
      iat: past, exp: past + 600, nonce: 'fixed-nonce-for-test-2',
      clientId: REQ_INFO.clientId, // deliberately disagrees with request.clientId
      redirectHash: await sha256Hex(REDIRECT_URI),
    };
    const state = await signPayload(SIGNING_KEY, payload);
    const result = await verifyStateStructure(SIGNING_KEY, state, REDIRECT_URI);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('client_mismatch');
  });
});

describe('state: nonce replay protection', () => {
  test('first consumption of a nonce succeeds', async () => {
    const kv = new FakeKV();
    const ok = await consumeStateNonce(kv as unknown as KVNamespace, 'nonce-a', 600);
    expect(ok).toBe(true);
  });

  test('reusing the same nonce is rejected', async () => {
    const kv = new FakeKV();
    const first = await consumeStateNonce(kv as unknown as KVNamespace, 'nonce-b', 600);
    const second = await consumeStateNonce(kv as unknown as KVNamespace, 'nonce-b', 600);
    expect(first).toBe(true);
    expect(second).toBe(false);
  });

  test('a full sign -> verify -> consume flow rejects replay on the second attempt', async () => {
    const kv = new FakeKV();
    const state = await signState(SIGNING_KEY, REQ_INFO, REDIRECT_URI);

    const firstVerify = await verifyStateStructure(SIGNING_KEY, state, REDIRECT_URI);
    expect(firstVerify.ok).toBe(true);
    if (!firstVerify.ok) return;
    const firstConsume = await consumeStateNonce(kv as unknown as KVNamespace, firstVerify.payload.nonce, 600);
    expect(firstConsume).toBe(true);

    // Attacker replays the exact same state value a second time.
    const secondVerify = await verifyStateStructure(SIGNING_KEY, state, REDIRECT_URI);
    expect(secondVerify.ok).toBe(true); // signature/expiry/etc are all still structurally valid...
    if (!secondVerify.ok) return;
    const secondConsume = await consumeStateNonce(kv as unknown as KVNamespace, secondVerify.payload.nonce, 600);
    expect(secondConsume).toBe(false); // ...but the nonce has already been spent.
  });
});

// Test-only helpers mirroring state.ts's private encode/sign logic, needed to
// construct payloads with specific (e.g. already-expired) fields that
// signState's real API doesn't allow controlling directly.
async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signPayload(signingKey: string, payload: unknown): Promise<string> {
  const payloadJson = JSON.stringify(payload);
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(signingKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadJson));
  return `${base64UrlEncodeBytes(new TextEncoder().encode(payloadJson))}.${base64UrlEncodeBytes(new Uint8Array(signature))}`;
}
