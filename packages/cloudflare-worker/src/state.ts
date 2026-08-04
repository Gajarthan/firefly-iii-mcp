/**
 * Signed, expiring, single-use `state` for the /authorize → Firefly III →
 * /callback round trip.
 *
 * The original MCP client's AuthRequest (oauthReqInfo) has to survive that
 * round trip somehow, and OAuth's `state` param is the standard place to
 * carry it (see e.g. Cloudflare's own remote-mcp-github-oauth demo). Firefly
 * only ever redirects back to our exact registered redirect_uri with a
 * `code` it minted itself, so state doesn't need to defend against a
 * forged /callback hit with an attacker-supplied code — it needs to defend
 * against a state value being tampered with, reused after it should have
 * expired, or replayed a second time.
 *
 * Payload: issued-at, expiry, a random nonce, the MCP client id, and a hash
 * of the redirect URI this state was minted for — HMAC-SHA256 signed with
 * MCP_STATE_SIGNING_KEY so tampering with any field invalidates the
 * signature. The nonce is additionally recorded in OAUTH_KV on first use so
 * a captured-and-replayed state (e.g. via browser history, a proxy log, a
 * referrer leak) can only ever complete the login flow once.
 */

const STATE_TTL_SECONDS = 10 * 60; // matches Firefly/Passport's own authorization-code lifetime ballpark

export interface StatePayload {
  request: unknown; // the original oauthReqInfo (AuthRequest) from env.OAUTH_PROVIDER.parseAuthRequest
  iat: number; // issued-at, epoch seconds
  exp: number; // expiry, epoch seconds
  nonce: string; // base64url random, single-use
  clientId: string; // duplicated from request.clientId - see verifyState's explicit client check
  redirectHash: string; // sha256 hex of the redirect_uri this state was minted for
}

const textEncoder = new TextEncoder();

const toHex = (bytes: ArrayBuffer): string =>
  Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');

const base64UrlEncodeBytes = (bytes: Uint8Array): string => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const base64UrlDecodeToBytes = (s: string): Uint8Array => {
  const binary = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
};

const base64UrlEncodeString = (s: string): string => base64UrlEncodeBytes(textEncoder.encode(s));
const base64UrlDecodeToString = (s: string): string => new TextDecoder().decode(base64UrlDecodeToBytes(s));

const sha256Hex = async (input: string): Promise<string> =>
  toHex(await crypto.subtle.digest('SHA-256', textEncoder.encode(input)));

const hmacKey = (signingKey: string): Promise<CryptoKey> =>
  crypto.subtle.importKey('raw', textEncoder.encode(signingKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

const randomNonce = (): string => base64UrlEncodeBytes(crypto.getRandomValues(new Uint8Array(18)));

export type StateValidationError =
  | 'malformed'
  | 'bad_signature'
  | 'expired'
  | 'client_mismatch'
  | 'redirect_mismatch'
  | 'replayed';

export type StateValidationResult =
  | { ok: true; payload: StatePayload }
  | { ok: false; error: StateValidationError };

/** Mints a signed, expiring state for one /authorize → Firefly → /callback round trip. */
export const signState = async (
  signingKey: string,
  oauthReqInfo: { clientId: string },
  redirectUri: string,
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  const payload: StatePayload = {
    request: oauthReqInfo,
    iat: now,
    exp: now + STATE_TTL_SECONDS,
    nonce: randomNonce(),
    clientId: oauthReqInfo.clientId,
    redirectHash: await sha256Hex(redirectUri),
  };
  const payloadJson = JSON.stringify(payload);
  const key = await hmacKey(signingKey);
  const signature = await crypto.subtle.sign('HMAC', key, textEncoder.encode(payloadJson));
  return `${base64UrlEncodeString(payloadJson)}.${base64UrlEncodeBytes(new Uint8Array(signature))}`;
};

/**
 * Verifies signature, expiry, client id, and redirect URI binding. Does NOT
 * check/consume the nonce - that needs the KV round trip, kept separate
 * (see consumeStateNonce) so a caller can fail fast on cheaper checks first
 * without touching KV at all for an already-invalid state.
 */
export const verifyStateStructure = async (
  signingKey: string,
  stateToken: string,
  currentRedirectUri: string,
): Promise<StateValidationResult> => {
  const parts = stateToken.split('.');
  if (parts.length !== 2) return { ok: false, error: 'malformed' };
  const [payloadPart, signaturePart] = parts;

  let payloadJson: string;
  let payload: StatePayload;
  try {
    payloadJson = base64UrlDecodeToString(payloadPart);
    payload = JSON.parse(payloadJson) as StatePayload;
  } catch {
    return { ok: false, error: 'malformed' };
  }
  if (
    typeof payload.iat !== 'number' || typeof payload.exp !== 'number' ||
    typeof payload.nonce !== 'string' || typeof payload.clientId !== 'string' ||
    typeof payload.redirectHash !== 'string' || typeof payload.request !== 'object'
  ) {
    return { ok: false, error: 'malformed' };
  }

  const key = await hmacKey(signingKey);
  const signatureBytes = base64UrlDecodeToBytes(signaturePart);
  const valid = await crypto.subtle.verify('HMAC', key, signatureBytes as BufferSource, textEncoder.encode(payloadJson));
  if (!valid) return { ok: false, error: 'bad_signature' };

  const now = Math.floor(Date.now() / 1000);
  if (now >= payload.exp) return { ok: false, error: 'expired' };

  const requestClientId = (payload.request as { clientId?: unknown }).clientId;
  if (requestClientId !== payload.clientId) return { ok: false, error: 'client_mismatch' };

  const currentRedirectHash = await sha256Hex(currentRedirectUri);
  if (currentRedirectHash !== payload.redirectHash) return { ok: false, error: 'redirect_mismatch' };

  return { ok: true, payload };
};

/**
 * Consistency note: Cloudflare KV writes propagate to the edge asynchronously
 * (documented "eventual consistency", commonly under 60s but not guaranteed
 * instant globally). Two /callback requests for the same state landing on
 * different edge colos within that propagation window could theoretically
 * both observe "not yet consumed" and both succeed - a narrow window, and
 * one that requires an attacker to have captured a valid, unexpired,
 * correctly-signed state token in the first place (see verifyStateStructure
 * above, which must already pass). For a two-user personal deployment this
 * residual risk is accepted; a stronger guarantee would need a Durable
 * Object as the single consistency point for nonce consumption instead of KV.
 *
 * Returns true if the nonce was successfully claimed (first use), false if
 * it was already present (replay).
 */
export const consumeStateNonce = async (kv: KVNamespace, nonce: string, ttlSeconds: number): Promise<boolean> => {
  const key = `state-nonce:${nonce}`;
  const existing = await kv.get(key);
  if (existing !== null) return false;
  // Cloudflare KV rejects expirationTtl below 60s.
  await kv.put(key, '1', { expirationTtl: Math.max(ttlSeconds, 60) });
  return true;
};
