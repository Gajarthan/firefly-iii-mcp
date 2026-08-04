/**
 * Structured, correlated JSON logging for the OAuth + tool-call pipeline.
 *
 * One correlationId is generated per inbound request at the edge (index.ts)
 * and threaded through every stage below it, so a single user request can
 * be traced end-to-end by grepping Cloudflare's log stream for that ID.
 *
 * Never pass a raw token, secret, code, password, Authorization header, or
 * full financial payload into `fields` - identifiers that could reveal who
 * a session belongs to (session id, grant id, Firefly user id) are hashed
 * with hashId() first, never logged raw.
 */

export type LogStage =
  | 'authorize'
  | 'callback'
  | 'token_exchange'
  | 'identity_lookup'
  | 'grant_creation'
  | 'token_refresh'
  | 'mcp_connection'
  | 'tool_invocation'
  | 'firefly_api_response';

export interface LogFields {
  correlationId: string;
  requestId?: string;
  sessionIdHash?: string;
  grantIdHash?: string;
  fireflyUserIdHash?: string;
  toolName?: string;
  stage: LogStage;
  durationMs?: number;
  upstreamStatus?: number;
  result: 'success' | 'failure';
  errorCode?: string;
}

// Fields that must never appear in a log line even by accident (e.g. someone
// later spreads an object that happens to carry one of these keys into
// logEvent's fields argument). Belt-and-suspenders alongside code review -
// see log.test.ts, which asserts logEvent's *output* never contains a
// plausible-looking token/secret regardless of what's passed in.
const FORBIDDEN_KEYS = new Set([
  'accessToken', 'fireflyAccessToken', 'refreshToken', 'fireflyRefreshToken',
  'code', 'clientSecret', 'authorization', 'password', 'token', 'secret',
  'notes', 'payload', 'body',
]);

const redact = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = FORBIDDEN_KEYS.has(k) ? '[redacted]' : redact(v);
    }
    return out;
  }
  return value;
};

export const newCorrelationId = (): string => crypto.randomUUID();

/** SHA-256, truncated to 16 hex chars - enough to correlate the same identifier across log lines without logging it raw. */
export const hashId = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
};

export const logEvent = (fields: LogFields): void => {
  const safeFields = redact(fields) as LogFields;
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...safeFields }));
};

/** Times an async stage and logs success/failure automatically, including errorCode on throw. */
export const withStageLogging = async <T>(
  fields: Omit<LogFields, 'result' | 'durationMs' | 'errorCode'>,
  fn: () => Promise<T>,
): Promise<T> => {
  const start = Date.now();
  try {
    const result = await fn();
    logEvent({ ...fields, result: 'success', durationMs: Date.now() - start });
    return result;
  } catch (error) {
    const errorCode = error instanceof Error && 'code' in error ? String((error as { code: unknown }).code) : undefined;
    logEvent({ ...fields, result: 'failure', durationMs: Date.now() - start, errorCode });
    throw error;
  }
};
