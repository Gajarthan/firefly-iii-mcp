import { describe, test, expect } from 'bun:test';
import { getMcpServerConfig } from './config';

const FAKE_ENV = {
  FIREFLY_III_BASE_URL: 'https://fin.example.test',
  MCP_TOOL_PRESET: 'safe',
  MCP_ENABLE_ADMIN_TOOLS: 'false',
} as unknown as Env;

describe('getMcpServerConfig', () => {
  test('returns undefined when there is no access token', () => {
    expect(getMcpServerConfig(FAKE_ENV, undefined)).toBeUndefined();
  });

  test('resolves baseUrl/pat/preset from env and the session token', () => {
    const config = getMcpServerConfig(FAKE_ENV, 'the-access-token');
    expect(config).toEqual({
      baseUrl: 'https://fin.example.test',
      pat: 'the-access-token',
      toolPreset: 'safe',
      includeAdmin: false,
      adminToolAllowlist: undefined,
    });
  });

  test('MCP_TOOL_PRESET=advanced is honored; anything else falls back to safe', () => {
    expect(getMcpServerConfig({ ...FAKE_ENV, MCP_TOOL_PRESET: 'advanced' } as Env, 'x')?.toolPreset).toBe('advanced');
    expect(getMcpServerConfig({ ...FAKE_ENV, MCP_TOOL_PRESET: 'nonsense' } as unknown as Env, 'x')?.toolPreset).toBe('safe');
  });

  /**
   * Regression test for the actual production incident this guards against:
   * McpAgent hands `props` to the FireflyIIIAgent Durable Object across an
   * RPC boundary, which requires structured-clone-compatible data. An
   * earlier version of index.ts spread a `logger` callback function into
   * this config before using it as DO props, which fails in production with
   * "DataCloneError: RpcStub cannot be serialized in this context" on every
   * real authenticated tool call - browser-only OAuth flow requests (which
   * never reach the DO) worked fine, masking the bug until a real MCP
   * client tried to actually list/call a tool. structuredClone() is the
   * same clone algorithm the DO RPC boundary uses, so this test fails the
   * same way production did if a function ever sneaks back in.
   */
  test('the resolved config (plus correlationId, as index.ts adds before passing it as DO props) is structured-clone-safe', () => {
    const config = getMcpServerConfig(FAKE_ENV, 'the-access-token');
    const withCorrelation = { ...config, correlationId: 'test-correlation-id' };
    expect(() => structuredClone(withCorrelation)).not.toThrow();
    for (const value of Object.values(withCorrelation)) {
      expect(typeof value).not.toBe('function');
    }
  });
});
