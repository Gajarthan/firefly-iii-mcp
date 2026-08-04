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

export const executeApiTool = async (
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
      const errors = validatedResult.errors;
      return {
        isError: true,
        content: [{
          type: 'text', text: JSON.stringify({
            message: `Invalid arguments for tool '${toolName}'`,
            errors: errors,
          }, null, 2)
        }]
      };
    }
  } catch (error: unknown) {
    return {
      isError: true,
      content: [{
        type: 'text', text: JSON.stringify({
          message: `Error validating arguments for tool '${toolName}'`,
          error: error,
        }, null, 2)
      }]
    }
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

  // Ensure all path parameters are resolved
  if (urlPath.includes('{')) {
    throw new Error(`Failed to resolve path parameters: ${urlPath}`);
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

  // Log request info to stderr (doesn't affect MCP output)
  console.debug(`Executing tool "${toolName}": ${requestMethod} ${requestEndpoint}`);

  const response = await fetch(requestUrl, {
    method: definition.method.toUpperCase(),
    headers: headers,
    body: requestBodyData ? JSON.stringify(requestBodyData) : undefined,
  });

  if (!response.ok) {
    const errorText = await response.text();
    // isError marks this as a failed call, which also exempts it from
    // outputSchema validation - error payloads do not match the success shape.
    return {
      isError: true,
      content: [{
        type: 'text', text: JSON.stringify({
          message: `Error executing tool '${toolName}': ${response.status} ${response.statusText}`,
          error: errorText,
        }, null, 2)
      }]
    }
  }

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
  return {
    isError: true,
    content: [{
      type: 'text', text: JSON.stringify({
        error: `Unsupported response type: ${responseType}`,
        message: `Unsupported response type: ${responseType}`,
      }, null, 2)
    }]
  }
}

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
    server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest): Promise<CallToolResult> => {
      return {
        content: [{
          type: "text", text: JSON.stringify({
            error: 'Unavailable',
            message: 'Please check your configuration and restart the server.',
          }, null, 2)
        }]
      };
    });
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
    server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest): Promise<CallToolResult> => {
      return {
        content: [{
          type: "text", text: JSON.stringify({
            error: 'Unauthorized',
            message: 'Please check your configuration and restart the server.',
          }, null, 2)
        }]
      };
    });
    return server;
  }

  const enableToolTags = serverConfig.enableToolTags ?? DEFAULT_PRESET_TAGS;

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const toolsForClient: Tool[] = generatedTools.filter(def => enableToolTags.length === 0 || enableToolTags.some(tag => def.tags.includes(tag))).map(def => ({
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
      console.error(`Error: Unknown tool requested: ${toolName}`);
      return { content: [{ type: "text", text: `Error: Unknown tool requested: ${toolName}` }] };
    }
    return await executeApiTool(toolName, toolDefinition, toolArgs ?? {}, serverConfig);
  });
  return server;
}
