/**
 * Local permission/risk metadata layered on top of the generated tool
 * definitions (tools.ts). Kept separate from McpToolDefinition so that
 * regenerating tools.ts from a newer Firefly III spec never overwrites
 * this classification - see scripts/generate-tool-risk.ts.
 */

/** Coarse severity label for a tool's blast radius if misused. */
export type ToolRisk = 'read' | 'write' | 'destructive' | 'administrative';

/** Which preset a tool must be enabled under to be reachable at all. */
export type ToolPreset = 'safe' | 'advanced' | 'administrative';

export interface ToolRiskEntry {
  risk: ToolRisk;
  requiredPreset: ToolPreset;
  /** Creates, modifies, deletes, or triggers a rule action on a transaction's amount/existence. */
  movesMoney: boolean;
  /** Permanently removes data with no undo path through the API. */
  permanentlyDeletesData: boolean;
  /** Touches data/identity belonging to (or visible to) an account other than the caller's own. */
  affectsOtherUsers: boolean;
  /** Should be surfaced to the calling agent/UI as needing explicit confirmation before firing. */
  requiresConfirmation: boolean;
}

/**
 * Most restrictive classification, used for any tool with no entry in
 * TOOL_RISK_MAP - e.g. a brand new tool introduced by regenerating tools.ts
 * from a newer Firefly III spec, before scripts/generate-tool-risk.ts has
 * been re-run and reviewed. Never resolves into 'safe' or 'advanced'.
 */
export const UNCLASSIFIED_TOOL_RISK: ToolRiskEntry = {
  risk: 'administrative',
  requiredPreset: 'administrative',
  movesMoney: false,
  permanentlyDeletesData: false,
  affectsOtherUsers: false,
  requiresConfirmation: true,
};
