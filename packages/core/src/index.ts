/**
 * Core module for Firefly III MCP
 * Export all key types, functions, and utilities
 */

// Export types
export type { McpServerConfig, McpToolDefinition, CallToolRequestArguments } from './types.js';

// Export server related functionality
export { getServer, executeApiTool } from './server.js';

// Export generated tools
export { generatedTools } from './tools.js';

// Export presets
export {
  ALL_TOOL_TAGS,
  DEFAULT_PRESET_TAGS,
  TOOL_PRESETS,
  getPresetTags,
  presetExists,
  getAvailablePresets
} from './presets.js';

// Export tool risk classification (safe/advanced/administrative presets)
export type { ToolRisk, ToolPreset, ToolRiskEntry } from './tool-risk-types.js';
export { UNCLASSIFIED_TOOL_RISK } from './tool-risk-types.js';
export { getToolRisk, resolveEnabledToolNames } from './tool-risk.js';
export type { ToolPresetConfig } from './tool-risk.js';

// Export the standardized error model
export type { McpErrorCode, McpErrorPayload } from './errors.js';
export { makeMcpError, classifyUpstreamStatus, extractSafeValidationMessage, upstreamError } from './errors.js';

export { Server } from '@modelcontextprotocol/sdk/server/index.js';