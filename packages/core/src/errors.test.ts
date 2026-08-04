import { describe, test, expect } from 'bun:test';
import { classifyUpstreamStatus, extractSafeValidationMessage, upstreamError, makeMcpError } from './errors.js';
import type { McpErrorCode } from './errors.js';

describe('classifyUpstreamStatus', () => {
  test.each([
    [401, 'UPSTREAM_UNAUTHORIZED'],
    [403, 'UPSTREAM_UNAUTHORIZED'],
    [400, 'UPSTREAM_VALIDATION_ERROR'],
    [422, 'UPSTREAM_VALIDATION_ERROR'],
    [429, 'UPSTREAM_RATE_LIMITED'],
    [500, 'UPSTREAM_UNAVAILABLE'],
    [502, 'UPSTREAM_UNAVAILABLE'],
    [503, 'UPSTREAM_UNAVAILABLE'],
    [418, 'INTERNAL_ERROR'],
  ])('%d -> %s', (status: number, expected: string) => {
    expect(classifyUpstreamStatus(status)).toBe(expected as McpErrorCode);
  });
});

describe('extractSafeValidationMessage', () => {
  test('extracts the message field from a well-formed Firefly validation error', () => {
    const body = JSON.stringify({ message: 'The amount field is required.', errors: { amount: ['required'] } });
    expect(extractSafeValidationMessage(body)).toBe('The amount field is required.');
  });

  test('returns undefined for non-JSON bodies', () => {
    expect(extractSafeValidationMessage('<html>not json</html>')).toBeUndefined();
  });

  test('returns undefined when the message field is missing', () => {
    expect(extractSafeValidationMessage(JSON.stringify({ errors: {} }))).toBeUndefined();
  });

  test('returns undefined when message is not a string', () => {
    expect(extractSafeValidationMessage(JSON.stringify({ message: 12345 }))).toBeUndefined();
  });
});

describe('upstreamError', () => {
  test('a 422 with a valid message body surfaces that message', () => {
    const body = JSON.stringify({ message: 'The name field is required.' });
    const err = upstreamError(422, body);
    expect(err.code).toBe('UPSTREAM_VALIDATION_ERROR');
    expect(err.message).toBe('The name field is required.');
    expect(err.retryable).toBe(false);
  });

  test('a 401 never leaks the raw response body, even if it were sensitive', () => {
    const body = JSON.stringify({ message: 'token abc123 rejected', internal_debug: 'stack trace here' });
    const err = upstreamError(401, body);
    expect(err.code).toBe('UPSTREAM_UNAUTHORIZED');
    expect(err.message).not.toContain('abc123');
    expect(err.message).not.toContain('stack trace');
  });

  test('a 500 never leaks the raw response body', () => {
    const body = 'Internal Server Error at /app/Controllers/SomeController.php:123';
    const err = upstreamError(500, body);
    expect(err.code).toBe('UPSTREAM_UNAVAILABLE');
    expect(err.message).not.toContain('SomeController.php');
    expect(err.retryable).toBe(true);
  });

  test('a 429 is marked retryable', () => {
    expect(upstreamError(429, '').retryable).toBe(true);
  });

  test('a 400 with an unparseable body still returns a safe generic message', () => {
    const err = upstreamError(400, 'not json at all');
    expect(err.code).toBe('UPSTREAM_VALIDATION_ERROR');
    expect(err.message).toBe('Firefly III rejected the request.');
  });
});

describe('makeMcpError', () => {
  test('sets retryable based on the error code', () => {
    expect(makeMcpError('UPSTREAM_RATE_LIMITED', 'x').retryable).toBe(true);
    expect(makeMcpError('UPSTREAM_UNAVAILABLE', 'x').retryable).toBe(true);
    expect(makeMcpError('INVALID_TOOL_INPUT', 'x').retryable).toBe(false);
    expect(makeMcpError('TOOL_DISABLED', 'x').retryable).toBe(false);
  });
});
