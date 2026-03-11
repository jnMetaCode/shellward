// src/layers/security-gate.ts — L5: Security Gate Tool (defense-in-depth via registerTool)

import { DANGEROUS_COMMANDS } from '../rules/dangerous-commands'
import { PROTECTED_PATHS } from '../rules/protected-paths'
import { resolveLocale } from '../types'
import type { ClawGuardConfig } from '../types'
import type { AuditLog } from '../audit-log'

function textResult(text: string) {
  return {
    content: [{ type: 'text' as const, text }],
    details: {},
  }
}

function checkAction(
  action: string,
  details: string,
  locale: 'zh' | 'en',
  log: AuditLog,
): { status: string; reason?: string } {
  // Check dangerous commands
  if (action === 'exec' || action === 'shell') {
    for (const rule of DANGEROUS_COMMANDS) {
      if (rule.pattern.test(details)) {
        const desc = locale === 'zh' ? rule.description_zh : rule.description_en
        log.write({
          level: 'CRITICAL',
          layer: 'L5',
          action: 'block',
          detail: `Gate denied: ${action} — ${desc}`,
          pattern: rule.id,
        })
        return { status: 'DENIED', reason: desc }
      }
    }
  }

  // Check protected paths
  if (action === 'file_delete' || action === 'file_write') {
    for (const rule of PROTECTED_PATHS) {
      if (rule.pattern.test(details)) {
        const desc = locale === 'zh' ? rule.description_zh : rule.description_en
        log.write({
          level: 'HIGH',
          layer: 'L5',
          action: 'block',
          detail: `Gate denied: ${action} — ${desc}`,
          pattern: rule.id,
        })
        return { status: 'DENIED', reason: desc }
      }
    }
  }

  // Block payment operations
  if (['payment', 'transfer', 'purchase'].includes(action)) {
    const reason = locale === 'zh'
      ? '安全策略禁止自动执行支付操作'
      : 'Payment operations are blocked by security policy'
    log.write({
      level: 'CRITICAL',
      layer: 'L5',
      action: 'block',
      detail: `Gate denied: ${action}`,
      pattern: 'no_payment',
    })
    return { status: 'DENIED', reason }
  }

  log.write({
    level: 'INFO',
    layer: 'L5',
    action: 'allow',
    detail: `Gate allowed: ${action}`,
  })
  return { status: 'ALLOWED' }
}

export function setupSecurityGate(
  api: any,
  config: ClawGuardConfig,
  log: AuditLog,
  enforce: boolean,
) {
  const locale = resolveLocale(config)

  if (!api.registerTool) {
    api.logger.warn('[ClawGuard] L5 Security Gate skipped: registerTool not available')
    return
  }

  const toolDescription = locale === 'zh'
    ? '在执行任何 Shell 命令、文件删除、邮件发送或支付操作前，必须先调用此工具进行安全检查。传入 action 类型和具体参数。'
    : 'MUST be called before executing any shell command, file deletion, email sending, or payment operation. Pass the action type and parameters for security review.'

  // registerTool expects AgentTool interface: { name, label, description, parameters, execute }
  api.registerTool({
    name: 'clawguard_check',
    label: 'ClawGuard Security Check',
    description: toolDescription,
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          description: 'The action to check: exec, file_delete, file_write, send_email, payment, etc.',
        },
        details: {
          type: 'string',
          description: 'The specific command, file path, or operation details',
        },
      },
      required: ['action', 'details'],
    },
    execute: async (
      _toolCallId: string,
      params: Record<string, unknown>,
    ) => {
      const action = String(params.action || '')
      const details = String(params.details || '')
      const result = checkAction(action, details, locale, log)
      return textResult(JSON.stringify(result))
    },
  })

  api.logger.info('[ClawGuard] L5 Security Gate registered')
}
