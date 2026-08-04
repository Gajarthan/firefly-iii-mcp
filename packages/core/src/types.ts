/**
 * Core type definitions for the openapi-to-mcp generator
 */
import type { OpenAPIV3 } from 'openapi-types';

/**
 * Upstream Config
 */
export type McpServerConfig = {
  baseUrl: string;
  /** Absent when the caller sends no credential; getServer() degrades to an 'unauthorized' stub tool in that case. */
  pat?: string;
  /** Legacy tag-based filter; still supported for the server/local packages. Superseded by toolPreset when set. */
  enableToolTags?: string[];
  /**
   * Preset-based filter (see tool-risk.ts). Takes priority over enableToolTags
   * when present. 'safe' and 'advanced' never expose administrative-tier
   * tools regardless of includeAdmin - that gate only ever widens which
   * *administrative* tools are reachable, on top of the base preset.
   */
  toolPreset?: 'safe' | 'advanced';
  /** Explicit opt-in to administrative tools; also requires adminToolAllowlist to name them. */
  includeAdmin?: boolean;
  /** Exact administrative tool names to enable when includeAdmin is true. */
  adminToolAllowlist?: string[];
  /**
   * Optional hook so a transport package (e.g. cloudflare-worker's log.ts)
   * can correlate tool_invocation/firefly_api_response stages into its own
   * structured request log. Deliberately a plain callback rather than a
   * dependency on any specific logging module - core stays agnostic about
   * how/where logs end up, and never sees the correlation id itself, only
   * gets to fire an event for one already bound to it by the caller.
   */
  logger?: (event: ToolInvocationLogEvent) => void;
}

export interface ToolInvocationLogEvent {
  stage: 'tool_invocation' | 'firefly_api_response';
  toolName: string;
  durationMs?: number;
  upstreamStatus?: number;
  result: 'success' | 'failure';
  errorCode?: string;
}

/** 
 * Execution parameter for a tool
 */
export interface ExecutionParameter {
  name: string;
  in: 'path' | 'query' | 'header';
}

/**
 * MCP Tool Definition describes a tool extracted from an OpenAPI spec
 * for use in Model Context Protocol server
 */
export interface McpToolDefinition {
  /** Name of the tool, must be unique */
  name: string;
  /** Tags of the tool, used to group tools */
  tags: string[];
  /** Human-readable description of the tool */
  description: string;
  /** JSON Schema that defines the input parameters */
  inputSchema: OpenAPIV3.SchemaObject;
  /** HTTP method for the operation (get, post, etc.) */
  method: string;
  /** URL path template with parameter placeholders */
  pathTemplate: string;
  /** OpenAPI parameter objects for this operation */
  // parameters: OpenAPIV3.ParameterObject[];
  /** Parameter names and locations for execution */
  executionParameters: ExecutionParameter[];
  /** Content type for request body, if applicable */
  requestBodyContentType?: string;
  /** Security requirements for this operation */
  // securityRequirements: OpenAPIV3.SecurityRequirementObject[];
  /** Original operation ID from the OpenAPI spec */
  operationId: string;
}

export type CallToolRequestArguments = Record<string, unknown>;