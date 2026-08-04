import { McpServerConfig } from "@firefly-iii-mcp/core";
import { getPresetTags } from "@firefly-iii-mcp/core";

/**
 * Builds the config used to talk to Firefly III for the logged-in session.
 *
 * Called only from inside the OAuthProvider's apiHandler (see index.ts),
 * which has already verified the caller holds a valid access token issued
 * through our own /authorize → Firefly III /oauth/authorize login, and has
 * decrypted that grant's Firefly access token into `ctx.props`. `pat` here
 * is that per-user Firefly III access token, not a static shared secret.
 */
export const getMcpServerConfig = (env: Env, fireflyAccessToken: string | undefined): McpServerConfig | undefined => {
  if (!fireflyAccessToken) return undefined;

  let enableToolTags: string[] | undefined = undefined;

  // Check for FIREFLY_III_TOOLS environment variable (higher priority)
  if (env.FIREFLY_III_TOOLS) {
    enableToolTags = env.FIREFLY_III_TOOLS.split(',').map(tag => tag.trim()).filter(Boolean);
  }
  // If FIREFLY_III_TOOLS is not set, check FIREFLY_III_PRESET
  else if (env.FIREFLY_III_PRESET) {
    try {
      enableToolTags = getPresetTags(env.FIREFLY_III_PRESET);
    } catch (error) {
      console.warn(`Warning: Error processing preset "${env.FIREFLY_III_PRESET}". Using default preset.`);
    }
  }

  return {
    baseUrl: env.FIREFLY_III_BASE_URL,
    pat: fireflyAccessToken,
    enableToolTags
  };
}
