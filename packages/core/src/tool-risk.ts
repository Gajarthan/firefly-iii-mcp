import type { McpToolDefinition } from './types.js';
import type { ToolPreset, ToolRiskEntry } from './tool-risk-types.js';
import { UNCLASSIFIED_TOOL_RISK } from './tool-risk-types.js';
import { TOOL_RISK_MAP } from './tool-risk-map.generated.js';

export type { ToolRisk, ToolPreset, ToolRiskEntry } from './tool-risk-types.js';
export { UNCLASSIFIED_TOOL_RISK } from './tool-risk-types.js';

/** Every tool resolves to a classification - falls back to the most restrictive one if unmapped. */
export const getToolRisk = (toolName: string): ToolRiskEntry => TOOL_RISK_MAP[toolName] ?? UNCLASSIFIED_TOOL_RISK;

/**
 * Presets nest: 'safe' is a strict subset of 'advanced' - every safe tool is
 * also usable under the advanced preset. 'administrative' tools are never
 * included by either; they only ever surface via resolveEnabledToolNames's
 * separate includeAdmin gate.
 */
const PRESET_INCLUDES: Record<Exclude<ToolPreset, 'administrative'>, ToolPreset[]> = {
  safe: ['safe'],
  advanced: ['safe', 'advanced'],
};

export interface ToolPresetConfig {
  /** Base preset - determines the non-administrative tool surface. */
  preset: 'safe' | 'advanced';
  /**
   * Explicit opt-in to also expose administrative-tier tools. Requires both
   * this flag AND an explicit allowlist (adminToolAllowlist) to actually
   * reach any administrative tool - a single flag is not sufficient, per
   * the hardening spec's "explicit tool allowlisting" requirement.
   */
  includeAdmin: boolean;
  /** Required when includeAdmin is true: the exact administrative tool names to enable. Ignored otherwise. */
  adminToolAllowlist?: string[];
}

/**
 * Resolves a preset config into the concrete set of tool names that should
 * be listed AND callable. This is the single source of truth both ListTools
 * and CallTool must consult - see server.ts, which enforces this at call
 * time too, not just at listing time.
 */
export const resolveEnabledToolNames = (allTools: McpToolDefinition[], config: ToolPresetConfig): Set<string> => {
  const allowedPresets = new Set<ToolPreset>(PRESET_INCLUDES[config.preset]);
  const adminAllowlist = config.includeAdmin ? new Set(config.adminToolAllowlist ?? []) : new Set<string>();

  const enabled = new Set<string>();
  for (const tool of allTools) {
    const { requiredPreset } = getToolRisk(tool.name);
    if (requiredPreset === 'administrative') {
      if (adminAllowlist.has(tool.name)) enabled.add(tool.name);
      continue;
    }
    if (allowedPresets.has(requiredPreset)) enabled.add(tool.name);
  }
  return enabled;
};
