#!/usr/bin/env npx tsx
// src/mcp-server.ts — ShellWard MCP Server
//
// Exposes ShellWard's 8-layer security engine as an MCP server.
// Zero dependencies — implements MCP protocol over stdio natively.
//
// Usage:
//   npx tsx src/mcp-server.ts
//
// MCP config (claude_desktop_config.json / openclaw settings):
//   {
//     "mcpServers": {
//       "shellward": {
//         "command": "npx",
//         "args": ["tsx", "/path/to/shellward/src/mcp-server.ts"]
//       }
//     }
//   }

import { ShellWard } from './core/engine.js'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'))

// ===== MCP Protocol Types =====

interface JsonRpcRequest {
  jsonrpc: '2.0'
  id?: number | string
  method: string
  params?: Record<string, unknown>
}

interface JsonRpcResponse {
  jsonrpc: '2.0'
  id: number | string | null
  result?: unknown
  error?: { code: number; message: string; data?: unknown }
}

// ===== ShellWard Instance =====

const guard = new ShellWard({
  mode: (process.env.SHELLWARD_MODE as 'enforce' | 'audit') || 'enforce',
  locale: (process.env.SHELLWARD_LOCALE as 'auto' | 'zh' | 'en') || 'auto',
  autoCheckOnStartup: false,
  layers: {
    promptGuard: true,
    outputScanner: true,
    toolBlocker: true,
    inputAuditor: true,
    securityGate: true,
    outboundGuard: true,
    dataFlowGuard: true,
    sessionGuard: true,
  },
  injectionThreshold: Number(process.env.SHELLWARD_THRESHOLD) || 60,
})

// ===== Tool Definitions =====

const TOOLS = [
  {
    name: 'check_command',
    description: 'Check if a shell command is safe to execute. Detects rm -rf, reverse shells, fork bombs, curl|sh, etc.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        command: { type: 'string', description: 'The shell command to check' },
      },
      required: ['command'],
    },
  },
  {
    name: 'check_injection',
    description: 'Detect prompt injection attempts in text. Supports 32+ rules for Chinese and English, with hidden character detection.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        text: { type: 'string', description: 'Text to scan for injection attempts' },
        threshold: { type: 'number', description: 'Detection threshold 0-100 (default: 60, lower = stricter)' },
      },
      required: ['text'],
    },
  },
  {
    name: 'scan_data',
    description: 'Scan text for sensitive data: PII (Chinese ID cards, phone numbers, bank cards), API keys, passwords, private keys, JWT tokens, SSN, credit cards.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        text: { type: 'string', description: 'Text to scan for sensitive data' },
      },
      required: ['text'],
    },
  },
  {
    name: 'check_path',
    description: 'Check if a file path operation is safe. Protects .env, .ssh/, .aws/credentials, private keys, /etc/passwd, etc.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'File path to check' },
        operation: { type: 'string', enum: ['write', 'delete'], description: 'Operation type' },
      },
      required: ['path', 'operation'],
    },
  },
  {
    name: 'check_tool',
    description: 'Check if a tool name is allowed. Blocks payment/transfer tools, flags exec/shell tools as sensitive.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        tool_name: { type: 'string', description: 'Tool name to check (e.g. "bash", "stripe_charge", "file_read")' },
      },
      required: ['tool_name'],
    },
  },
  {
    name: 'check_response',
    description: 'Check an AI response for security issues: canary token leaks and sensitive data exposure.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        content: { type: 'string', description: 'Response content to check' },
      },
      required: ['content'],
    },
  },
  {
    name: 'security_status',
    description: 'Get current ShellWard security status: mode, active layers, detection capabilities.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
]

// ===== Tool Execution =====

function executeTool(name: string, args: Record<string, unknown>): unknown {
  switch (name) {
    case 'check_command': {
      const result = guard.checkCommand(String(args.command || ''))
      return {
        safe: result.allowed,
        level: result.level || null,
        reason: result.reason || null,
        rule_id: result.ruleId || null,
      }
    }

    case 'check_injection': {
      const opts = typeof args.threshold === 'number' ? { threshold: args.threshold } : undefined
      const result = guard.checkInjection(String(args.text || ''), opts)
      return {
        safe: result.safe,
        score: result.score,
        threshold: result.threshold,
        matched_rules: result.matched.map((m: any) => ({
          id: m.id,
          name: m.name,
          score: m.score,
        })),
        hidden_chars: result.hiddenChars,
      }
    }

    case 'scan_data': {
      const result = guard.scanData(String(args.text || ''))
      return {
        has_sensitive_data: result.hasSensitiveData,
        findings: result.findings.map((f: any) => ({
          type: f.id,
          name: f.name,
          count: f.count,
        })),
        summary: result.summary,
      }
    }

    case 'check_path': {
      const op = String(args.operation || '')
      if (op !== 'write' && op !== 'delete') {
        throw new Error(`Invalid operation: "${op}". Must be "write" or "delete".`)
      }
      const result = guard.checkPath(String(args.path || ''), op)
      return {
        safe: result.allowed,
        level: result.level || null,
        reason: result.reason || null,
        rule_id: result.ruleId || null,
      }
    }

    case 'check_tool': {
      const result = guard.checkTool(String(args.tool_name || ''))
      return {
        allowed: result.allowed,
        level: result.level || null,
        reason: result.reason || null,
      }
    }

    case 'check_response': {
      const result = guard.checkResponse(String(args.content || ''))
      return {
        canary_leak: result.canaryLeak,
        has_sensitive_data: result.sensitiveData.hasSensitiveData,
        findings: result.sensitiveData.findings.map(f => ({
          type: f.id,
          name: f.name,
          count: f.count,
        })),
      }
    }

    case 'security_status': {
      return {
        mode: guard.config.mode,
        locale: guard.locale,
        injection_threshold: guard.config.injectionThreshold,
        layers: guard.config.layers,
        capabilities: [
          'command_safety_check (17 dangerous patterns)',
          'prompt_injection_detection (32+ rules, zh+en)',
          'pii_detection (CN ID/phone/bank + global)',
          'path_protection (12 protected patterns)',
          'tool_policy (block payment/transfer)',
          'response_audit (canary + PII)',
          'data_flow_tracking (DLP)',
        ],
      }
    }

    default:
      throw new Error(`Unknown tool: ${name}`)
  }
}

// ===== MCP Protocol Handlers =====

function handleRequest(req: JsonRpcRequest): JsonRpcResponse | null {
  const { id, method, params } = req

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id: id ?? null,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: {
            name: 'shellward',
            version: pkg.version,
          },
        },
      }

    case 'notifications/initialized':
      // Client acknowledgement, no response needed
      return null

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id: id ?? null,
        result: { tools: TOOLS },
      }

    case 'resources/list':
      return { jsonrpc: '2.0', id: id ?? null, result: { resources: [] } }

    case 'prompts/list':
      return { jsonrpc: '2.0', id: id ?? null, result: { prompts: [] } }

    case 'tools/call': {
      const toolName = (params as any)?.name as string
      const toolArgs = ((params as any)?.arguments || {}) as Record<string, unknown>

      try {
        const result = executeTool(toolName, toolArgs)
        return {
          jsonrpc: '2.0',
          id: id ?? null,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          },
        }
      } catch (err: any) {
        return {
          jsonrpc: '2.0',
          id: id ?? null,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ error: err.message }),
              },
            ],
            isError: true,
          },
        }
      }
    }

    case 'ping':
      return { jsonrpc: '2.0', id: id ?? null, result: {} }

    default:
      // Unknown methods — return error for requests with id, ignore notifications
      if (id !== undefined) {
        return {
          jsonrpc: '2.0',
          id: id ?? null,
          error: { code: -32601, message: `Method not found: ${method}` },
        }
      }
      return null
  }
}

// ===== Stdio Transport =====
// Use raw Buffer to handle UTF-8 multi-byte characters correctly.
// Content-Length is in bytes, not characters.

let rawBuffer = Buffer.alloc(0)

process.stdin.on('data', (chunk: Buffer) => {
  rawBuffer = Buffer.concat([rawBuffer, chunk])

  while (true) {
    const headerEnd = rawBuffer.indexOf('\r\n\r\n')
    if (headerEnd === -1) break

    const header = rawBuffer.slice(0, headerEnd).toString('ascii')
    const lengthMatch = header.match(/Content-Length:\s*(\d+)/i)
    if (!lengthMatch) {
      rawBuffer = rawBuffer.slice(headerEnd + 4)
      continue
    }

    const contentLength = parseInt(lengthMatch[1], 10)
    const bodyStart = headerEnd + 4
    if (rawBuffer.length < bodyStart + contentLength) break

    const body = rawBuffer.slice(bodyStart, bodyStart + contentLength).toString('utf8')
    rawBuffer = rawBuffer.slice(bodyStart + contentLength)

    try {
      const req = JSON.parse(body) as JsonRpcRequest
      const res = handleRequest(req)
      if (res) {
        send(res)
      }
    } catch {
      send({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      })
    }
  }
})

function send(msg: JsonRpcResponse) {
  const body = JSON.stringify(msg)
  const header = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n`
  process.stdout.write(header + body)
}

process.stdin.on('end', () => process.exit(0))

// Log to stderr so it doesn't interfere with stdio protocol
process.stderr.write(`[ShellWard MCP] Server started (mode: ${guard.config.mode}, locale: ${guard.locale})\n`)
