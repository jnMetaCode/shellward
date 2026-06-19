#!/usr/bin/env node
// src/mcp-server.ts — ShellWard MCP Server
//
// Exposes ShellWard's 8-layer security engine as an MCP server.
// Zero dependencies — implements MCP protocol over stdio (newline-delimited JSON).
//
// Run (production, after `npm run build` or `npm i -g shellward`):
//   shellward-mcp           # via the published bin
//   node dist/mcp-server.js # direct
//
// Run (development, from source):
//   npm run mcp             # npx tsx src/mcp-server.ts
//
// MCP config (claude_desktop_config.json / openclaw settings):
//   {
//     "mcpServers": {
//       "shellward": {
//         "command": "shellward-mcp"
//       }
//     }
//   }

import { ShellWard } from './core/engine.js'
import { McpBaseline } from './mcp-baseline.js'
import { runComplianceAudit } from './compliance/audit.js'
import { renderComplianceReport } from './compliance/report.js'
import { readFileSync } from 'fs'
import { createInterface } from 'readline'
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
  injectionThreshold: Number(process.env.SHELLWARD_THRESHOLD) || 40,
})

// Rug-pull baseline store (lazy-persisted; only used when a `server` is supplied).
// SHELLWARD_BASELINE_PATH relocates the store (tests/sandboxes use a temp file).
const baseline = new McpBaseline(process.env.SHELLWARD_BASELINE_PATH || undefined)

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
    description: 'Detect prompt injection attempts in text. Supports 37+ rules for Chinese and English, with hidden character detection.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        text: { type: 'string', description: 'Text to scan for injection attempts' },
        threshold: { type: 'number', description: 'Detection threshold 0-100 (default: 40, lower = stricter)' },
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
    name: 'scan_mcp_tool',
    description: 'Scan an MCP tool definition for tool-poisoning (hidden/invisible-character instructions, concealment directives, sensitive-file access, exfiltration hints) AND rug-pull (description silently changed since first seen). Pass a tool as { name, description, inputSchema }; provide "server" to enable rug-pull baselining.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Tool name' },
        description: { type: 'string', description: 'Tool description to scan' },
        inputSchema: { type: 'object', description: 'Tool JSON Schema (optional) — nested parameter descriptions are scanned too' },
        server: { type: 'string', description: 'MCP server name (optional) — enables rug-pull detection by fingerprinting the tool across runs' },
        threshold: { type: 'number', description: 'Detection threshold (default: 40)' },
      },
      required: ['name'],
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
  {
    name: 'compliance_check',
    description: 'Run a China AI-compliance health check (网安法/PIPL/等保2.0/数据出境/AI标识) and return a red/yellow/green scorecard report. Detects overseas LLM endpoints (data-export risk), audit-log retention, enabled defense layers, and root execution.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        format: { type: 'string', enum: ['report', 'json'], description: 'Output format: "report" (Markdown scorecard, default) or "json" (raw result)' },
      },
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

    case 'scan_mcp_tool': {
      const tool = {
        name: String(args.name || 'unknown'),
        description: typeof args.description === 'string' ? args.description : undefined,
        inputSchema: (args.inputSchema && typeof args.inputSchema === 'object')
          ? (args.inputSchema as Record<string, unknown>)
          : undefined,
      }
      const result = guard.scanToolDefinition(
        tool,
        typeof args.threshold === 'number' ? { threshold: args.threshold } : undefined,
      )

      // Optional rug-pull detection: fingerprint the tool across runs.
      let rugPull: { status: string; changed: boolean } | null = null
      if (typeof args.server === 'string' && args.server) {
        const rp = baseline.record(McpBaseline.keyFor(args.server, tool.name), tool)
        baseline.save()
        rugPull = { status: rp.status, changed: rp.status === 'changed' }
      }

      return {
        tool_name: result.toolName,
        safe: result.safe && !(rugPull?.changed),
        score: result.score,
        threshold: result.threshold,
        hidden_chars: result.hiddenChars,
        rug_pull: rugPull,
        findings: result.findings.map(f => ({
          id: f.id,
          name: f.name,
          category: f.category,
          score: f.score,
          source: f.source,
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
          'prompt_injection_detection (37+ rules, zh+en)',
          'mcp_tool_poisoning_scan (description + schema)',
          'pii_detection (CN ID/phone/bank + global)',
          'path_protection (12 protected patterns)',
          'tool_policy (block payment/transfer)',
          'response_audit (canary + PII)',
          'data_flow_tracking (DLP)',
        ],
      }
    }

    case 'compliance_check': {
      const report = runComplianceAudit(guard.config)
      if (args.format === 'json') {
        return {
          score: report.score,
          grade: report.grade,
          passed: report.passed,
          warned: report.warned,
          failed: report.failed,
          manual: report.manual,
          total: report.total,
          results: report.results.map(r => ({
            id: r.control.id,
            regulation: r.control.regulation,
            article: r.control.article,
            title: guard.locale === 'zh' ? r.control.title_zh : r.control.title_en,
            status: r.status,
            detail: guard.locale === 'zh' ? r.detail_zh : r.detail_en,
          })),
        }
      }
      // default: return Markdown report as text
      return { report: renderComplianceReport(report, guard.locale) }
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
          protocolVersion: '2025-03-26',
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
// MCP stdio: newline-delimited JSON-RPC messages (no Content-Length framing).
// Each message is a single JSON object followed by \n.
// Messages MUST NOT contain embedded newlines.

const rl = createInterface({ input: process.stdin, terminal: false })

rl.on('line', (line: string) => {
  const trimmed = line.trim()
  if (!trimmed) return

  try {
    const req = JSON.parse(trimmed) as JsonRpcRequest
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
})

function send(msg: JsonRpcResponse) {
  process.stdout.write(JSON.stringify(msg) + '\n')
}

rl.on('close', () => process.exit(0))
process.stdin.on('error', () => process.exit(1))

// Log to stderr so it doesn't interfere with stdio protocol
process.stderr.write(`[ShellWard MCP] Server started (mode: ${guard.config.mode}, locale: ${guard.locale})\n`)
