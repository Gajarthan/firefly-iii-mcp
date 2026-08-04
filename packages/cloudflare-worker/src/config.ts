import { McpServerConfig } from "@firefly-iii-mcp/core";

/**
 * Builds the config used to talk to Firefly III for the logged-in session.
 *
 * Called only from inside the OAuthProvider's apiHandler (see index.ts),
 * which has already verified the caller holds a valid access token issued
 * through our own /authorize → Firefly III /oauth/authorize login, and has
 * decrypted that grant's Firefly access token into `ctx.props`. `pat` here
 * is that per-user Firefly III access token, not a static shared secret.
 *
 * Tool exposure is preset-based (MCP_TOOL_PRESET), not tag-based - see
 * @firefly-iii-mcp/core's tool-risk.ts. Administrative tools require BOTH
 * MCP_ENABLE_ADMIN_TOOLS=true AND naming each one explicitly in
 * MCP_ADMIN_TOOL_ALLOWLIST; setting the flag alone enables nothing, per the
 * hardening spec's "explicit tool allowlisting" requirement.
 */
export const getMcpServerConfig = (env: Env, fireflyAccessToken: string | undefined): McpServerConfig | undefined => {
  if (!fireflyAccessToken) return undefined;

  const toolPreset: 'safe' | 'advanced' = env.MCP_TOOL_PRESET === 'advanced' ? 'advanced' : 'safe';
  const includeAdmin = env.MCP_ENABLE_ADMIN_TOOLS === 'true';
  const adminToolAllowlist = includeAdmin
    ? (env.MCP_ADMIN_TOOL_ALLOWLIST ?? '').split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;

  return {
    baseUrl: env.FIREFLY_III_BASE_URL,
    pat: fireflyAccessToken,
    toolPreset,
    includeAdmin,
    adminToolAllowlist,
  };
}
