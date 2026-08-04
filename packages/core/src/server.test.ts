import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { getServer } from './server.js';
import type { McpServerConfig } from './types.js';

// The SDK's Server/Protocol class stores registered handlers in a Map keyed
// by JSON-RPC method name (see node_modules/@modelcontextprotocol/sdk/dist/
// esm/shared/protocol.js, setRequestHandler). Invoking them directly here
// avoids standing up a real transport just to exercise ListTools/CallTool.
const listTools = (server: ReturnType<typeof getServer>) =>
  (server as any)._requestHandlers.get('tools/list')({ method: 'tools/list', params: {} }, {});

const callTool = (server: ReturnType<typeof getServer>, name: string, args: Record<string, unknown> = {}) =>
  (server as any)._requestHandlers.get('tools/call')({ method: 'tools/call', params: { name, arguments: args } }, {});

const BASE_CONFIG: McpServerConfig = {
  baseUrl: 'https://fin.example.test',
  pat: 'the-users-firefly-access-token',
  toolPreset: 'safe',
  includeAdmin: false,
};

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = globalThis.fetch; });
afterEach(() => { globalThis.fetch = originalFetch; });

describe('getServer: safe preset tool discovery', () => {
  test('lists only safe-tier tools by default', async () => {
    const server = getServer(BASE_CONFIG);
    const { tools } = await listTools(server);
    const names = tools.map((t: { name: string }) => t.name);
    expect(names).toContain('list_account');
    expect(names).toContain('store_transaction');
    expect(names).not.toContain('delete_transaction');
    expect(names).not.toContain('store_bill');
  });

  test('administrative tools are absent from discovery even with includeAdmin set but no allowlist', async () => {
    const server = getServer({ ...BASE_CONFIG, includeAdmin: true });
    const { tools } = await listTools(server);
    const names = tools.map((t: { name: string }) => t.name);
    expect(names).not.toContain('destroy_data');
    expect(names).not.toContain('store_user');
  });

  test('administrative tools appear only when explicitly allowlisted', async () => {
    const server = getServer({ ...BASE_CONFIG, includeAdmin: true, adminToolAllowlist: ['store_user'] });
    const { tools } = await listTools(server);
    const names = tools.map((t: { name: string }) => t.name);
    expect(names).toContain('store_user');
    expect(names).not.toContain('delete_user');
  });
});

describe('getServer: disabled tools cannot be invoked by name', () => {
  test('a tool absent from the safe preset is rejected with TOOL_DISABLED when called directly, not silently executed', async () => {
    globalThis.fetch = mock(async () => jsonResponse({ data: {} })) as unknown as typeof fetch;
    const server = getServer(BASE_CONFIG); // safe preset - delete_transaction is advanced-tier
    const result = await callTool(server, 'delete_transaction', { id: '1' });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.code).toBe('TOOL_DISABLED');
    // The critical regression this guards: the upstream call must never
    // have been attempted for a disabled tool.
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('an administrative tool is rejected even if the caller already knows its exact name', async () => {
    globalThis.fetch = mock(async () => jsonResponse({ data: {} })) as unknown as typeof fetch;
    const server = getServer(BASE_CONFIG);
    const result = await callTool(server, 'destroy_data', { objects: 'transactions' });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.code).toBe('TOOL_DISABLED');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('a tool enabled under the advanced preset IS callable there', async () => {
    globalThis.fetch = mock(async () => new Response(null, { status: 204 })) as unknown as typeof fetch;
    const server = getServer({ ...BASE_CONFIG, toolPreset: 'advanced' });
    const result = await callTool(server, 'delete_transaction', { id: '1' });
    expect(result.isError).toBeFalsy();
  });
});

describe('getServer: safe tools remain usable', () => {
  test('a valid safe-tier tool call reaches Firefly III and returns its data', async () => {
    globalThis.fetch = mock(async () => jsonResponse({ data: { id: '1', attributes: { name: 'Checking' } } })) as unknown as typeof fetch;
    const server = getServer(BASE_CONFIG);
    const result = await callTool(server, 'get_account', { id: '1' });
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent.data.attributes.name).toBe('Checking');
  });
});

describe('getServer: missing/expired session credential', () => {
  test('no pat -> ListTools returns only the stub "unauthorized" tool', async () => {
    const server = getServer({ baseUrl: 'https://fin.example.test' }); // no pat
    const { tools } = await listTools(server);
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe('unauthorized');
  });

  test('no pat -> CallTool is rejected with AUTHENTICATION_REQUIRED, never reaches Firefly', async () => {
    globalThis.fetch = mock(async () => jsonResponse({})) as unknown as typeof fetch;
    const server = getServer({ baseUrl: 'https://fin.example.test' });
    const result = await callTool(server, 'list_account', {});
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.code).toBe('AUTHENTICATION_REQUIRED');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});

describe('getServer: upstream error handling', () => {
  test('an upstream 401 is mapped to UPSTREAM_UNAUTHORIZED, not passed through raw', async () => {
    globalThis.fetch = mock(async () => new Response(
      JSON.stringify({ message: 'Token invalid or expired.' }),
      { status: 401, headers: { 'content-type': 'application/json' } },
    )) as unknown as typeof fetch;
    const server = getServer(BASE_CONFIG);
    const result = await callTool(server, 'list_account', {});
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.code).toBe('UPSTREAM_UNAUTHORIZED');
  });

  test('the caller\'s own bearer token never appears anywhere in an error response', async () => {
    globalThis.fetch = mock(async () => new Response(
      `Full traceback mentioning Bearer ${BASE_CONFIG.pat} somewhere in a buggy upstream error page`,
      { status: 500 },
    )) as unknown as typeof fetch;
    const server = getServer(BASE_CONFIG);
    const result = await callTool(server, 'list_account', {});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).not.toContain(BASE_CONFIG.pat as string);
  });

  test('invalid tool arguments are rejected before any upstream call is made', async () => {
    globalThis.fetch = mock(async () => jsonResponse({})) as unknown as typeof fetch;
    const server = getServer(BASE_CONFIG);
    // get_account requires an "id"; omit it.
    const result = await callTool(server, 'get_account', {});
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.code).toBe('INVALID_TOOL_INPUT');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});

describe('getServer: structured logging via correlationId', () => {
  // correlationId is a plain string (not a callback) specifically because
  // McpServerConfig crosses a Durable Object RPC boundary on the deployed
  // worker - see McpServerConfig.correlationId's doc comment. These tests
  // capture console.log output rather than passing in a function, since a
  // function is exactly what must NOT be relied on here.
  let originalConsoleLog: typeof console.log;
  let capturedLines: string[];
  beforeEach(() => {
    capturedLines = [];
    originalConsoleLog = console.log;
    console.log = mock((line: string) => { capturedLines.push(line); });
  });
  afterEach(() => { console.log = originalConsoleLog; });

  const parsedLogEvents = () => capturedLines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);

  test('a tool_invocation event with toolName and result is logged for both success and failure', async () => {
    globalThis.fetch = mock(async () => jsonResponse({ data: {} })) as unknown as typeof fetch;
    const server = getServer({ ...BASE_CONFIG, correlationId: 'test-correlation-1' });

    await callTool(server, 'get_account', { id: '1' });
    const invocationEvents = parsedLogEvents().filter((e) => e.stage === 'tool_invocation');
    expect(invocationEvents.length).toBe(1);
    expect(invocationEvents[0].toolName).toBe('get_account');
    expect(invocationEvents[0].result).toBe('success');
    expect(invocationEvents[0].correlationId).toBe('test-correlation-1');
  });

  test('a TOOL_DISABLED rejection is logged too, so blocked attempts are still observable', async () => {
    const server = getServer({ ...BASE_CONFIG, correlationId: 'test-correlation-2' });
    await callTool(server, 'delete_transaction', { id: '1' });
    const events = parsedLogEvents();
    expect(events.some((e) => e.stage === 'tool_invocation' && e.errorCode === 'TOOL_DISABLED')).toBe(true);
  });

  test('no correlationId set -> nothing is logged (server/local packages opt out by omission)', async () => {
    globalThis.fetch = mock(async () => jsonResponse({ data: {} })) as unknown as typeof fetch;
    const server = getServer(BASE_CONFIG); // no correlationId
    await callTool(server, 'get_account', { id: '1' });
    expect(capturedLines.length).toBe(0);
  });
});
