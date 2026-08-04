import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { logEvent, hashId, newCorrelationId } from './log';

let capturedLines: string[];
let originalConsoleLog: typeof console.log;

beforeEach(() => {
  capturedLines = [];
  originalConsoleLog = console.log;
  console.log = mock((line: string) => { capturedLines.push(line); });
});
afterEach(() => { console.log = originalConsoleLog; });

const SECRET_LOOKING_VALUES = [
  'ey.fake.jwt.access.token.value',
  'firefly-refresh-token-abc123',
  'oauth-authorization-code-xyz',
  'super-secret-client-secret',
  'Bearer some-access-token',
  'hunter2-password',
];

describe('logEvent: redaction', () => {
  test('emits valid JSON with the expected base fields', () => {
    logEvent({ correlationId: 'corr-1', stage: 'authorize', result: 'success' });
    expect(capturedLines.length).toBe(1);
    const parsed = JSON.parse(capturedLines[0]);
    expect(parsed.correlationId).toBe('corr-1');
    expect(parsed.stage).toBe('authorize');
    expect(parsed.result).toBe('success');
    expect(typeof parsed.ts).toBe('string');
  });

  test('a forbidden-key field (accessToken) is redacted, not printed', () => {
    logEvent({
      correlationId: 'corr-2', stage: 'token_exchange', result: 'success',
      // @ts-expect-error - deliberately passing a field the type doesn't declare, to prove logEvent's own redaction is what protects it, not just the type system.
      accessToken: 'ey.fake.jwt.access.token.value',
    });
    const line = capturedLines[0];
    expect(line).not.toContain('ey.fake.jwt.access.token.value');
    expect(line).toContain('[redacted]');
  });

  test('every known secret-shaped value stays out of the emitted line when passed under a forbidden key', () => {
    for (const secret of SECRET_LOOKING_VALUES) {
      capturedLines = [];
      logEvent({
        correlationId: 'corr-3', stage: 'callback', result: 'failure',
        // @ts-expect-error - see above.
        token: secret,
      });
      expect(capturedLines[0]).not.toContain(secret);
    }
  });

  test('nested objects are redacted recursively', () => {
    logEvent({
      correlationId: 'corr-4', stage: 'grant_creation', result: 'success',
      // @ts-expect-error - see above.
      extra: { nested: { refreshToken: 'nested-secret-value' } },
    });
    expect(capturedLines[0]).not.toContain('nested-secret-value');
  });

  test('non-secret fields (toolName, upstreamStatus, durationMs) pass through untouched', () => {
    logEvent({
      correlationId: 'corr-5', stage: 'tool_invocation', result: 'success',
      toolName: 'list_account', upstreamStatus: 200, durationMs: 42,
    });
    const parsed = JSON.parse(capturedLines[0]);
    expect(parsed.toolName).toBe('list_account');
    expect(parsed.upstreamStatus).toBe(200);
    expect(parsed.durationMs).toBe(42);
  });
});

describe('hashId', () => {
  test('is deterministic for the same input', async () => {
    const a = await hashId('firefly-user-1');
    const b = await hashId('firefly-user-1');
    expect(a).toBe(b);
  });

  test('different inputs hash to different values', async () => {
    const a = await hashId('firefly-user-1');
    const b = await hashId('firefly-user-2');
    expect(a).not.toBe(b);
  });

  test('never returns the raw input value', async () => {
    const raw = 'some-sensitive-identifier';
    const hashed = await hashId(raw);
    expect(hashed).not.toBe(raw);
    expect(hashed).not.toContain(raw);
  });
});

describe('newCorrelationId', () => {
  test('produces distinct ids across calls', () => {
    const ids = new Set(Array.from({ length: 20 }, () => newCorrelationId()));
    expect(ids.size).toBe(20);
  });
});
