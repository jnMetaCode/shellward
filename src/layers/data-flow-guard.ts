// src/layers/data-flow-guard.ts — L7: Cross-tool data flow tracking
// Detects: read sensitive file → send via network tool (data exfiltration chain)
// Uses: after_tool_call (track reads) + before_tool_call (block exfil sends)

import { PROTECTED_PATHS } from '../rules/protected-paths'
import { resolveLocale } from '../types'
import type { ShellWardConfig } from '../types'
import type { AuditLog } from '../audit-log'

// Network/outbound tools that could exfiltrate data
const NETWORK_TOOLS = new Set([
  'web_fetch', 'http_request', 'web_search',
  'send_email', 'send_message', 'post_tweet',
  'message', 'sessions_send',
])

// Read tools that access local files
const READ_TOOLS = new Set([
  'read', 'file_read', 'cat', 'exec', 'bash',
])

// Package install commands that could run postinstall scripts
const PKG_INSTALL_PATTERN = /(?:npm|yarn|pnpm)\s+(?:install|add|i)\s|pip\s+install\s|gem\s+install\s/i

// Track sensitive file reads within a session (tool call IDs or content hashes)
const sensitiveReads: Map<string, { path: string; ts: number }> = new Map()
const TRACKING_WINDOW_MS = 5 * 60 * 1000 // 5 min window
const MAX_TRACKED_READS = 500 // Prevent unbounded memory growth

export function setupDataFlowGuard(
  api: any,
  config: ShellWardConfig,
  log: AuditLog,
  enforce: boolean,
) {
  const locale = resolveLocale(config)

  // === Part 1: Track sensitive file reads via after_tool_call ===
  api.on('after_tool_call', (event: any) => {
    const toolName = String(event.toolName || '').toLowerCase()
    const params = (event.params && typeof event.params === 'object') ? event.params : {}
    const path = String(params.path || params.file_path || params.filename || '')

    if (!READ_TOOLS.has(toolName) || !path) return

    // Check if it's a protected/sensitive path
    for (const rule of PROTECTED_PATHS) {
      if (rule.pattern.test(path)) {
        // Evict oldest entry if at capacity
        if (sensitiveReads.size >= MAX_TRACKED_READS) {
          const oldest = sensitiveReads.keys().next().value
          if (oldest) sensitiveReads.delete(oldest)
        }
        const key = `${Date.now()}-${path}`
        sensitiveReads.set(key, { path, ts: Date.now() })

        log.write({
          level: 'MEDIUM',
          layer: 'L7',
          action: 'detect',
          detail: locale === 'zh'
            ? `检测到敏感文件读取: ${path} — 已加入数据流监控`
            : `Sensitive file read detected: ${path} — added to data flow tracking`,
          tool: event.toolName,
          pattern: rule.id,
        })
        break
      }
    }

    // Cleanup old entries
    const now = Date.now()
    for (const [key, val] of sensitiveReads) {
      if (now - val.ts > TRACKING_WINDOW_MS) {
        sensitiveReads.delete(key)
      }
    }
  }, { name: 'shellward.data-flow-read-tracker', priority: 50 })

  // === Part 2: Block network tool calls if sensitive data was recently read ===
  api.on('before_tool_call', (event: any) => {
    const toolName = String(event.toolName || '').toLowerCase()
    const params = (event.params && typeof event.params === 'object') ? event.params : {}

    // 2a. Block network tools if sensitive files were recently read
    if (NETWORK_TOOLS.has(toolName) && sensitiveReads.size > 0) {
      // Clean up expired entries first
      const now = Date.now()
      for (const [key, val] of sensitiveReads) {
        if (now - val.ts > TRACKING_WINDOW_MS) sensitiveReads.delete(key)
      }

      if (sensitiveReads.size > 0) {
        const recentPaths = [...sensitiveReads.values()].map(v => v.path).join(', ')
        const reason = locale === 'zh'
          ? `数据外泄风险: 最近读取了敏感文件 (${recentPaths})，禁止调用网络工具 ${event.toolName}`
          : `Data exfiltration risk: sensitive files recently read (${recentPaths}), blocking network tool ${event.toolName}`

        log.write({
          level: 'CRITICAL',
          layer: 'L7',
          action: enforce ? 'block' : 'detect',
          detail: reason,
          tool: event.toolName,
          pattern: 'data_exfil_chain',
        })

        if (enforce) {
          return { block: true, blockReason: `🚫 [ShellWard] ${reason}` }
        }
      }
    }

    // 2b. Check URL parameters in network tools for suspicious patterns
    if (NETWORK_TOOLS.has(toolName)) {
      const url = String(params.url || params.to || params.target || '')
      if (url) {
        // Block data-in-URL exfiltration patterns
        if (/[?&](?:data|token|key|secret|password|content)=/i.test(url)) {
          const reason = locale === 'zh'
            ? `可疑 URL 参数: ${url.slice(0, 80)} — 可能是数据外泄`
            : `Suspicious URL params: ${url.slice(0, 80)} — possible data exfiltration`

          log.write({
            level: 'HIGH',
            layer: 'L7',
            action: enforce ? 'block' : 'detect',
            detail: reason,
            tool: event.toolName,
            pattern: 'url_data_exfil',
          })

          if (enforce) {
            return { block: true, blockReason: `🚫 [ShellWard] ${reason}` }
          }
        }
      }
    }

    // 2c. Detect dangerous package installs
    if (toolName === 'exec' || toolName === 'bash') {
      const cmd = String(params.command || params.cmd || '')
      if (PKG_INSTALL_PATTERN.test(cmd)) {
        log.write({
          level: 'MEDIUM',
          layer: 'L7',
          action: 'detect',
          detail: locale === 'zh'
            ? `检测到包安装命令: ${cmd.slice(0, 80)} — 注意供应链安全`
            : `Package install detected: ${cmd.slice(0, 80)} — supply chain risk`,
          tool: event.toolName,
          pattern: 'pkg_install',
        })
      }
    }
  }, { name: 'shellward.data-flow-egress', priority: 250 })

  api.logger.info('[ShellWard] L7 Data Flow Guard enabled')
}
