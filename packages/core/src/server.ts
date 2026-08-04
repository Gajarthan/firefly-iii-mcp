import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  Tool,
  CallToolRequestSchema,
  CallToolRequest,
  CallToolResult
} from "@modelcontextprotocol/sdk/types.js";
import { CallToolRequestArguments, McpServerConfig, McpToolDefinition } from "./types.js";
import { generatedTools } from "./tools.js";
import { Schema, Validator } from "@cfworker/json-schema";
import { openapiSchemaToJsonSchema } from "@openapi-contrib/openapi-schema-to-json-schema";
import { DEFAULT_PRESET_TAGS } from "./presets.js";
import { resolveEnabledToolNames } from "./tool-risk.js";
import { makeMcpError, upstreamError, McpErrorPayload } from "./errors.js";

/**
 * Build the JSON Schema describing a tool's result.
 *
 * Derived from the tool definition at list time rather than baked into the
 * generated tools.ts, so regenerating that file from the OpenAPI spec cannot
 * silently drop it.
 *
 * Deliberately permissive: every object allows additional properties and
 * nothing is marked required. A declared outputSchema obliges us to return
 * matching structuredContent on every success, so a schema that is too strict
 * turns a working call into a client-side validation error. These describe the
 * Firefly III v1 envelope without promising more than the API guarantees.
 */
export const buildOutputSchema = (definition: McpToolDefinition): { type: 'object';[k: string]: unknown } => {
  // All delete_* tools answer 204 with an empty body; see executeApiTool.
  if (definition.method.toLowerCase() === 'delete') {
    return {
      type: 'object',
      properties: {
        success: { type: 'boolean', description: 'True when Firefly III accepted the deletion.' },
        status: { type: 'number', description: 'HTTP status returned by Firefly III (204 on success).' },
      },
      additionalProperties: false,
    };
  }

  // Not an envelope: a map of summary keys ("balance-in-LKR", "spent-in-LKR", ...)
  // onto summary entries.
  if (definition.name === 'get_basic_summary') {
    return {
      type: 'object',
      description: 'Map of summary key to summary entry.',
      additionalProperties: { type: 'object', additionalProperties: true },
    };
  }

  const isCollection = /^(list_|search_)/.test(definition.name);
  return {
    type: 'object',
    properties: {
      data: isCollection
        ? {
          type: 'array',
          description: 'The requested resources.',
          items: { type: 'object', additionalProperties: true },
        }
        : {
          type: 'object',
          description: 'The requested resource.',
          additionalProperties: true,
        },
      meta: {
        type: 'object',
        description: 'Response metadata, including pagination for collections.',
        additionalProperties: true,
      },
      links: {
        type: 'object',
        description: 'Navigation links for the resource or collection.',
        additionalProperties: true,
      },
    },
    additionalProperties: true,
  };
};

const errorResult = (error: McpErrorPayload): CallToolResult => ({
  isError: true,
  content: [{ type: 'text', text: JSON.stringify(error, null, 2) }],
});

const extractErrorCode = (result: CallToolResult): string | undefined => {
  try {
    const first = result.content?.[0];
    const text = first && first.type === 'text' ? (first as { text: string }).text : undefined;
    if (!text) return undefined;
    const parsed = JSON.parse(text) as { code?: unknown };
    return typeof parsed.code === 'string' ? parsed.code : undefined;
  } catch {
    return undefined;
  }
};

export const executeApiTool = async (
  toolName: string,
  definition: McpToolDefinition,
  toolArgs: CallToolRequestArguments,
  serverConfig: McpServerConfig,
): Promise<CallToolResult> => {
  const startedAt = Date.now();
  const result = await executeApiToolInner(toolName, definition, toolArgs, serverConfig);
  serverConfig.logger?.({
    stage: 'tool_invocation',
    toolName,
    durationMs: Date.now() - startedAt,
    result: result.isError ? 'failure' : 'success',
    errorCode: result.isError ? extractErrorCode(result) : undefined,
  });
  return result;
};

const executeApiToolInner = async (
  toolName: string,
  definition: McpToolDefinition,
  toolArgs: CallToolRequestArguments,
  serverConfig: McpServerConfig,
): Promise<CallToolResult> => {
  let validatedArgs: CallToolRequestArguments;
  try {
    // Validate arguments against the input schema
    const schema = openapiSchemaToJsonSchema(definition.inputSchema);
    const validator = new Validator(schema as Schema, '4')
    const argsToParse = (typeof toolArgs === 'object' && toolArgs !== null) ? toolArgs : {};
    const validatedResult = validator.validate(argsToParse);
    if (validatedResult.valid) {
      validatedArgs = argsToParse;
    } else {
      const summary = validatedResult.errors.map((e) => `${e.instanceLocation || '(root)'}: ${e.error}`).join('; ');
      return errorResult(makeMcpError('INVALID_TOOL_INPUT', `Invalid arguments for tool '${toolName}': ${summary}`));
    }
  } catch {
    return errorResult(makeMcpError('INVALID_TOOL_INPUT', `Error validating arguments for tool '${toolName}'`));
  }

  // Prepare URL, query parameters, headers, and request body
  let urlPath = definition.pathTemplate;
  const queryParams: Record<string, any> = {};
  const headers: Record<string, string> = { 'Accept': 'application/json' };
  let requestBodyData: unknown = undefined;

  // Apply parameters to the URL path, query, or headers
  definition.executionParameters.forEach((param) => {
    const value = validatedArgs[param.name];
    if (typeof value !== 'undefined' && value !== null) {
      if (param.in === 'path') {
        urlPath = urlPath.replace(`{${param.name}}`, encodeURIComponent(String(value)));
      }
      else if (param.in === 'query') {
        queryParams[param.name] = value;
      }
      else if (param.in === 'header') {
        headers[param.name.toLowerCase()] = String(value);
      }
    }
  });

  // Ensure all path parameters are resolved. This indicates a bug in the
  // generated tool definition (a param the spec declared but we never
  // received an execution mapping for), not a caller-input problem - still
  // must not throw uncaught, or the raw JS error/stack reaches the MCP
  // client via the SDK's default error handling.
  if (urlPath.includes('{')) {
    return errorResult(makeMcpError('INTERNAL_ERROR', `Tool '${toolName}' has an unresolved path parameter.`));
  }

  // Handle request body if needed
  if (definition.requestBodyContentType && typeof validatedArgs['requestBody'] !== 'undefined') {
    requestBodyData = validatedArgs['requestBody'];
    headers['content-type'] = definition.requestBodyContentType;
  }

  /**
   * Used Preloaded Security Schemes, ignored for now
   */
  const { pat, baseUrl } = serverConfig;
  headers['Authorization'] = `Bearer ${pat}`;

  // Construct the full URL
  const requestEndpoint = `${baseUrl}/api${urlPath}`
  const requestUrl = queryParams ? `${requestEndpoint}?${new URLSearchParams(queryParams).toString()}` : requestEndpoint;
  const requestMethod = definition.method.toUpperCase();

  // Log request info to stderr (doesn't affect MCP output). Path/method only
  // - never headers (carries the bearer token) or the request body.
  console.debug(`Executing tool "${toolName}": ${requestMethod} ${requestEndpoint}`);

  const upstreamStartedAt = Date.now();
  let response: Response;
  try {
    response = await fetch(requestUrl, {
      method: definition.method.toUpperCase(),
      headers: headers,
      body: requestBodyData ? JSON.stringify(requestBodyData) : undefined,
    });
  } catch {
    serverConfig.logger?.({
      stage: 'firefly_api_response', toolName, durationMs: Date.now() - upstreamStartedAt,
      result: 'failure', errorCode: 'UPSTREAM_UNAVAILABLE',
    });
    // Network failure reaching Firefly III itself (DNS, TLS, connection
    // refused) - not an HTTP error response, so classifyUpstreamStatus
    // doesn't apply; treated the same as upstream being down.
    return errorResult(makeMcpError('UPSTREAM_UNAVAILABLE', 'Could not reach Firefly III.'));
  }

  if (!response.ok) {
    const errorText = await response.text();
    const mapped = upstreamError(response.status, errorText);
    serverConfig.logger?.({
      stage: 'firefly_api_response', toolName, durationMs: Date.now() - upstreamStartedAt,
      upstreamStatus: response.status, result: 'failure', errorCode: mapped.code,
    });
    console.debug(`Tool "${toolName}" upstream error: ${response.status}`);
    // isError marks this as a failed call, which also exempts it from
    // outputSchema validation - error payloads do not match the success shape.
    return errorResult(mapped);
  }

  serverConfig.logger?.({
    stage: 'firefly_api_response', toolName, durationMs: Date.now() - upstreamStartedAt,
    upstreamStatus: response.status, result: 'success',
  });

  const responseType = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();

  // 204 No Content, or a body with no content-type: every delete_* tool lands
  // here. Previously this fell through to the "unsupported response type"
  // branch and reported a successful delete as an error.
  if (response.status === 204 || !responseType) {
    const outcome = { success: true, status: response.status };
    return {
      content: [{
        type: 'text', text: JSON.stringify(outcome, null, 2)
      }],
      structuredContent: outcome,
    }
  }

  if (responseType.includes('json')) {
    const responseData = await response.json();
    // structuredContent must be a JSON object; wrap anything else so the
    // result still satisfies the declared outputSchema.
    const structuredContent = (typeof responseData === 'object' && responseData !== null && !Array.isArray(responseData))
      ? responseData as Record<string, unknown>
      : { data: responseData };
    return {
      content: [{
        type: 'text', text: JSON.stringify(responseData, null, 2)
      }],
      structuredContent,
    }
  } else if (responseType.includes('text')) {
    const responseText = await response.text();
    return {
      content: [{
        type: 'text', text: responseText
      }],
      structuredContent: { data: responseText },
    }
  }

  // Default to text response for unsupported types
  return errorResult(makeMcpError('INTERNAL_ERROR', `Unsupported response type from Firefly III: ${responseType}`));
}

/**
 * Resolves which tool names this config actually enables. Preset-based
 * (toolPreset/includeAdmin/adminToolAllowlist) takes priority when set;
 * falls back to the legacy tag-based enableToolTags for the server/local
 * packages that haven't adopted presets, and finally to DEFAULT_PRESET_TAGS
 * to preserve prior default behavior when neither is configured.
 *
 * This is the single source of truth for BOTH ListTools and CallTool -
 * previously only ListTools consulted the filter, so a client that already
 * knew a disabled tool's name (from a prior session, documentation, or a
 * guess) could invoke it anyway. See getServer() below.
 */
const resolveEnabledTools = (serverConfig: McpServerConfig): Set<string> => {
  if (serverConfig.toolPreset) {
    return resolveEnabledToolNames(generatedTools, {
      preset: serverConfig.toolPreset,
      includeAdmin: serverConfig.includeAdmin ?? false,
      adminToolAllowlist: serverConfig.adminToolAllowlist,
    });
  }
  const tags = serverConfig.enableToolTags ?? DEFAULT_PRESET_TAGS;
  if (tags.length === 0) return new Set(generatedTools.map((t) => t.name));
  return new Set(generatedTools.filter((def) => tags.some((tag) => def.tags.includes(tag))).map((t) => t.name));
};

/**
 * Get the MCP server instance
 * @param serverConfig - The server configuration
 * @returns The MCP server instance
 */
export const getServer = (serverConfig: McpServerConfig): Server => {
  const server = new Server(
    {
      name: 'Firefly III MCP Agent',
      version: '1.4.0',
    }, {
    capabilities: { tools: {} }
  })

  if (!serverConfig.baseUrl) {
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      const unavailableTool: Tool = {
        name: 'unavailable',
        description: 'This tool is not available because the base URL is not configured. Please check your configuration and restart the server.',
        inputSchema: {
          type: 'object'
        },
        outputSchema: {
          type: 'object',
          properties: {
            error: {
              type: 'string',
              description: 'The error message'
            },
            message: {
              type: 'string',
              description: 'The error message'
            }
          }
        }
      }
      return { tools: [unavailableTool] }
    })
    server.setRequestHandler(CallToolRequestSchema, async (): Promise<CallToolResult> =>
      errorResult(makeMcpError('AUTHENTICATION_REQUIRED', 'Please check your configuration and restart the server.'))
    );
    return server;
  }

  if (!serverConfig.pat) {
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      const unauthorizedTool: Tool = {
        name: 'unauthorized',
        description: 'This tool is not available because the user is not authenticated. Please check your configuration and restart the server.',
        inputSchema: {
          type: 'object'
        },
        outputSchema: {
          type: 'object',
          properties: {
            error: {
              type: 'string',
              description: 'The error message'
            },
            message: {
              type: 'string',
              description: 'The error message'
            }
          }
        }
      }
      return { tools: [unauthorizedTool] }
    })
    server.setRequestHandler(CallToolRequestSchema, async (): Promise<CallToolResult> =>
      errorResult(makeMcpError('AUTHENTICATION_REQUIRED', 'Please check your configuration and restart the server.'))
    );
    return server;
  }

  const enabledToolNames = resolveEnabledTools(serverConfig);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const toolsForClient: Tool[] = generatedTools.filter(def => enabledToolNames.has(def.name)).map(def => ({
      name: def.name,
      description: def.description,
      inputSchema: {
        ...def.inputSchema,
        type: 'object',
      },
      outputSchema: buildOutputSchema(def),
    }));
    return { tools: toolsForClient };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest): Promise<CallToolResult> => {
    const { name: toolName, arguments: toolArgs } = request.params;
    const toolDefinition = generatedTools.find(tool => tool.name === toolName);
    if (!toolDefinition) {
      return errorResult(makeMcpError('INVALID_TOOL_INPUT', `Unknown tool requested: ${toolName}`));
    }
    // Enforced here, not just in ListTools - a tool absent from tool
    // discovery must also be unreachable by a client that already knows
    // (or guesses) its name.
    if (!enabledToolNames.has(toolName)) {
      serverConfig.logger?.({ stage: 'tool_invocation', toolName, result: 'failure', errorCode: 'TOOL_DISABLED' });
      return errorResult(makeMcpError('TOOL_DISABLED', `Tool '${toolName}' is disabled under the current preset configuration.`));
    }
    return await executeApiTool(toolName, toolDefinition, toolArgs ?? {}, serverConfig);
  });
  return server;
}
