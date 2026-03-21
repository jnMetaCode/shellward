// src/layers/security-gate.ts — L5 OpenClaw Adapter
// Thin adapter: registers shellward_check tool via OpenClaw's registerTool API

import type { ShellWard } from '../core/engine.js'

function textResult(text: string) {
  return {
    content: [{ type: 'text' as const, text }],
    details: {},
  }
}

export function setupSecurityGate(api: any, guard: ShellWard, enforce: boolean) {
  if (!api.registerTool) {
    api.logger.warn('[ShellWard] L5 Security Gate skipped: registerTool not available')
    return
  }

  const toolDescription = guard.locale === 'zh'
    ? '在执行任何 Shell 命令、文件删除、邮件发送或支付操作前，必须先调用此工具进行安全检查。传入 action 类型和具体参数。'
    : 'MUST be called before executing any shell command, file deletion, email sending, or payment operation. Pass the action type and parameters for security review.'

  api.registerTool({
    name: 'shellward_check',
    label: 'ShellWard Security Check',
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
    execute: async (_toolCallId: string, params: Record<string, unknown>) => {
      const action = typeof params.action === 'string' ? params.action.trim() : ''
      const details = typeof params.details === 'string' ? params.details.trim() : ''
      if (!action) {
        return textResult(JSON.stringify({ status: 'DENIED', reason: 'action parameter is required' }))
      }
      const result = guard.checkAction(action, details)
      return textResult(JSON.stringify({
        status: result.allowed ? 'ALLOWED' : 'DENIED',
        reason: result.reason,
      }))
    },
  })

  api.logger.info('[ShellWard] L5 Security Gate registered')
}
