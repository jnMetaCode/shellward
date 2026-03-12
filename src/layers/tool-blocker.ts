// src/layers/tool-blocker.ts — L3: Block dangerous tool calls via before_tool_call hook

import { DANGEROUS_COMMANDS, splitCommands } from '../rules/dangerous-commands'
import { PROTECTED_PATHS } from '../rules/protected-paths'
import { resolveLocale } from '../types'
import type { ShellWardConfig, ResolvedLocale } from '../types'
import type { AuditLog } from '../audit-log'
import { resolve } from 'path'

// Tools that are always blocked (lowercase for case-insensitive matching)
const BLOCKED_TOOLS = new Set([
  'payment', 'transfer', 'purchase',
  'stripe_charge', 'paypal_send',
])

// Tools that get logged but not blocked (lowercase)
const SENSITIVE_TOOLS = new Set([
  'send_email', 'delete_email',
  'send_message', 'post_tweet',
  'file_delete', 'skill_install',
])

// Tool names that execute shell commands (lowercase)
const EXEC_TOOLS = new Set([
  'exec', 'shell_exec', 'run_command', 'bash',
])

export function setupToolBlocker(
  api: any,
  config: ShellWardConfig,
  log: AuditLog,
  enforce: boolean,
) {
  const locale = resolveLocale(config)

  api.on('before_tool_call', (event: any) => {
    const tool: string = String(event.toolName || '')
    const toolLower = tool.toLowerCase()
    const args: Record<string, any> = (event.params && typeof event.params === 'object') ? event.params : {}

    // 1. Always-blocked tools (case-insensitive)
    if (BLOCKED_TOOLS.has(toolLower)) {
      const reason = locale === 'zh'
        ? `安全策略禁止自动执行: ${tool}`
        : `Blocked by security policy: ${tool}`

      log.write({
        level: 'CRITICAL',
        layer: 'L3',
        action: enforce ? 'block' : 'detect',
        detail: reason,
        tool,
      })

      if (enforce) {
        return { block: true, blockReason: `🚫 [ShellWard] ${reason}` }
      }
      return
    }

    // 2. Dangerous shell command detection (case-insensitive tool match)
    if (EXEC_TOOLS.has(toolLower)) {
      const rawCmd = args.command ?? args.cmd ?? ''
      const cmd = typeof rawCmd === 'string' ? rawCmd : ''
      // Split on command separators to catch chained attacks like "echo hi; rm -rf /"
      const parts = splitCommands(cmd)
      for (const part of parts) {
        const result = checkDangerousCommand(part, locale, tool, log, enforce)
        if (result) return result
      }
    }

    // 3. Protected path detection (normalize path first)
    const rawPath = String(args.path || args.file_path || args.filename || args.target || '')
    if (rawPath && isWriteOrDeleteTool(toolLower)) {
      // Resolve path to prevent ../ traversal bypass
      const normalizedPath = normalizePath(rawPath)
      const result = checkProtectedPath(normalizedPath, locale, tool, log, enforce)
      if (result) return result
    }

    // 4. Log sensitive tool usage (case-insensitive)
    if (SENSITIVE_TOOLS.has(toolLower)) {
      log.write({
        level: 'MEDIUM',
        layer: 'L3',
        action: 'detect',
        detail: `Sensitive tool used: ${tool}`,
        tool,
      })
    }

  }, { name: 'shellward.tool-blocker', priority: 200 })

  api.logger.info('[ShellWard] L3 Tool Blocker enabled')
}

function checkDangerousCommand(
  cmd: string,
  locale: ResolvedLocale,
  tool: string,
  log: AuditLog,
  enforce: boolean,
): { block: true; blockReason: string } | undefined {
  for (const rule of DANGEROUS_COMMANDS) {
    if (rule.pattern.test(cmd)) {
      const desc = locale === 'zh' ? rule.description_zh : rule.description_en
      const reason = locale === 'zh'
        ? `检测到危险命令: ${truncate(cmd, 80)}\n原因: ${desc}`
        : `Dangerous command: ${truncate(cmd, 80)}\nReason: ${desc}`

      log.write({
        level: 'CRITICAL',
        layer: 'L3',
        action: enforce ? 'block' : 'detect',
        detail: reason,
        tool,
        pattern: rule.id,
      })

      if (enforce) {
        return { block: true, blockReason: `🚫 [ShellWard] ${reason}` }
      }
      return
    }
  }
}

function checkProtectedPath(
  path: string,
  locale: ResolvedLocale,
  tool: string,
  log: AuditLog,
  enforce: boolean,
): { block: true; blockReason: string } | undefined {
  for (const rule of PROTECTED_PATHS) {
    if (rule.pattern.test(path)) {
      const desc = locale === 'zh' ? rule.description_zh : rule.description_en
      const reason = locale === 'zh'
        ? `禁止操作受保护路径: ${path}\n原因: ${desc}`
        : `Protected path blocked: ${path}\nReason: ${desc}`

      log.write({
        level: 'HIGH',
        layer: 'L3',
        action: enforce ? 'block' : 'detect',
        detail: reason,
        tool,
        pattern: rule.id,
      })

      if (enforce) {
        return { block: true, blockReason: `🚫 [ShellWard] ${reason}` }
      }
      return
    }
  }
}

function isWriteOrDeleteTool(toolLower: string): boolean {
  return /write|delete|remove|overwrite|truncate|edit/.test(toolLower)
}

/**
 * Normalize path: resolve ../ traversal, expand ~, lowercase for comparison
 */
function normalizePath(p: string): string {
  // Expand ~ to HOME
  const expanded = p.startsWith('~')
    ? p.replace(/^~/, process.env.HOME || '/root')
    : p
  // Resolve ../ and ./ sequences
  try {
    return resolve(expanded)
  } catch {
    return expanded
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + '...' : s
}
