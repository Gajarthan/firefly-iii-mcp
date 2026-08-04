/**
 * Safe, predictable error categories for anything that can reach an MCP
 * client - tool-call failures, and (in the cloudflare-worker package) the
 * OAuth flow's own JSON-facing failure responses. Never construct one of
 * these from a raw upstream response body, JS Error.stack, or Cloudflare
 * error page; those go to structured logs (see log.ts in cloudflare-worker)
 * for operator diagnosis, not to the caller.
 */
export type McpErrorCode =
  | 'AUTHENTICATION_REQUIRED'
  | 'AUTHORIZATION_FAILED'
  | 'TOKEN_REFRESH_FAILED'
  | 'UPSTREAM_UNAUTHORIZED'
  | 'UPSTREAM_VALIDATION_ERROR'
  | 'UPSTREAM_RATE_LIMITED'
  | 'UPSTREAM_UNAVAILABLE'
  | 'TOOL_DISABLED'
  | 'INVALID_TOOL_INPUT'
  | 'INTERNAL_ERROR';

export interface McpErrorPayload {
  code: McpErrorCode;
  message: string;
  /** True if retrying the same request later has a reasonable chance of succeeding. */
  retryable: boolean;
}

const RETRYABLE_CODES: ReadonlySet<McpErrorCode> = new Set(['UPSTREAM_RATE_LIMITED', 'UPSTREAM_UNAVAILABLE']);

export const makeMcpError = (code: McpErrorCode, message: string): McpErrorPayload => ({
  code,
  message,
  retryable: RETRYABLE_CODES.has(code),
});

/**
 * Maps a Firefly III API HTTP status to a safe error code. Deliberately
 * ignores the response body here - callers that want to surface a Firefly
 * validation message use extractSafeValidationMessage below instead, which
 * only trusts the structured `message` field of a 400/422 response.
 */
export const classifyUpstreamStatus = (status: number): McpErrorCode => {
  if (status === 401 || status === 403) return 'UPSTREAM_UNAUTHORIZED';
  if (status === 400 || status === 422) return 'UPSTREAM_VALIDATION_ERROR';
  if (status === 429) return 'UPSTREAM_RATE_LIMITED';
  if (status >= 500) return 'UPSTREAM_UNAVAILABLE';
  return 'INTERNAL_ERROR';
};

/**
 * Firefly III's 400/422 responses are `{ message: string, errors?: {...} }`
 * - genuinely useful, non-secret, user-actionable feedback (e.g. "the
 * amount field is required"). Everything else about an upstream error
 * response (full body, headers, stack) is not safe to forward verbatim, so
 * this is the one deliberate exception: only the `message` string, only for
 * validation-class statuses, and only if the body actually parses as the
 * expected shape.
 */
export const extractSafeValidationMessage = (bodyText: string): string | undefined => {
  try {
    const parsed = JSON.parse(bodyText) as unknown;
    if (parsed && typeof parsed === 'object' && 'message' in parsed && typeof (parsed as { message: unknown }).message === 'string') {
      return (parsed as { message: string }).message;
    }
  } catch {
    // Not JSON, or not the expected shape - fall through to no message.
  }
  return undefined;
};

/** Builds the safe, client-facing error for a failed upstream Firefly III call. */
export const upstreamError = (status: number, bodyText: string): McpErrorPayload => {
  const code = classifyUpstreamStatus(status);
  if (code === 'UPSTREAM_VALIDATION_ERROR') {
    const detail = extractSafeValidationMessage(bodyText);
    return makeMcpError(code, detail ?? 'Firefly III rejected the request.');
  }
  const genericMessages: Partial<Record<McpErrorCode, string>> = {
    UPSTREAM_UNAUTHORIZED: 'Firefly III rejected the current session credentials.',
    UPSTREAM_RATE_LIMITED: 'Firefly III is rate-limiting requests; try again shortly.',
    UPSTREAM_UNAVAILABLE: 'Firefly III is temporarily unavailable.',
    INTERNAL_ERROR: 'Firefly III returned an unexpected response.',
  };
  return makeMcpError(code, genericMessages[code] ?? 'Firefly III returned an unexpected response.');
};
