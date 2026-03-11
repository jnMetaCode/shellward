// src/layers/tool-blocker.ts — L3: Block dangerous tool calls via before_tool_call hook

import { DANGEROUS_COMMANDS } from '../rules/dangerous-commands'
import { PROTECTED_PATHS } from '../rules/protected-paths'
import { resolveLocale } from '../types'
import type { ClawGuardConfig, ResolvedLocale } from '../types'
import type { AuditLog } from '../audit-log'

// Tools that are always blocked
const BLOCKED_TOOLS = new Set([
  'payment', 'transfer', 'purchase',
  'stripe_charge', 'paypal_send',
])

// Tools that get logged but not blocked
const SENSITIVE_TOOLS = new Set([
  'send_email', 'delete_email',
  'send_message', 'post_tweet',
  'file_delete', 'skill_install',
])

// Tool names that execute shell commands
const EXEC_TOOLS = new Set([
  'exec', 'shell_exec', 'run_command', 'bash', 'Bash',
])

export function setupToolBlocker(
  api: any,
  config: ClawGuardConfig,
  log: AuditLog,
  enforce: boolean,
) {
  const locale = resolveLocale(config)

  api.on('before_tool_call', (event: any) => {
    const tool: string = event.tool || ''
    const args: Record<string, any> = event.arguments || {}

    // 1. Always-blocked tools
    if (BLOCKED_TOOLS.has(tool)) {
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
        return { block: true, blockReason: `🚫 [ClawGuard] ${reason}` }
      }
      return
    }

    // 2. Dangerous shell command detection
    if (EXEC_TOOLS.has(tool)) {
      const cmd = String(args.command || args.cmd || '')
      const result = checkDangerousCommand(cmd, locale, tool, log, enforce)
      if (result) return result
    }

    // 3. Protected path detection
    const path = String(args.path || args.file_path || args.filename || args.target || '')
    if (path && isWriteOrDeleteTool(tool)) {
      const result = checkProtectedPath(path, locale, tool, log, enforce)
      if (result) return result
    }

    // 4. Log sensitive tool usage
    if (SENSITIVE_TOOLS.has(tool)) {
      log.write({
        level: 'MEDIUM',
        layer: 'L3',
        action: 'detect',
        detail: `Sensitive tool used: ${tool}`,
        tool,
      })
    }

  }, { name: 'clawguard.tool-blocker', priority: 200 })

  api.logger.info('[ClawGuard] L3 Tool Blocker enabled')
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
        return { block: true, blockReason: `🚫 [ClawGuard] ${reason}` }
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
        return { block: true, blockReason: `🚫 [ClawGuard] ${reason}` }
      }
      return
    }
  }
}

function isWriteOrDeleteTool(tool: string): boolean {
  return /write|delete|remove|overwrite|truncate/i.test(tool)
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + '...' : s
}
