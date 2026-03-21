// src/layers/input-auditor.ts — L4 OpenClaw Adapter
// Thin adapter: wires OpenClaw hooks to ShellWard core engine for injection detection
// Compat: registers all known hook name variants — OpenClaw silently ignores unknown ones

import type { ShellWard } from '../core/engine.js'

export function setupInputAuditor(api: any, guard: ShellWard, enforce: boolean) {
  // Tool call parameter scanning via before_tool_call
  api.on('before_tool_call', (event: any) => {
    const args: Record<string, any> = (event.params && typeof event.params === 'object') ? event.params : {}
    const texts = guard.extractTextFields(args)
    if (texts.length === 0) return

    const toolName = String(event.toolName || '')
    const threshold = guard.getInjectionThreshold(toolName)
    const fullText = texts.join('\n')
    const result = guard.checkInjection(fullText, { source: toolName, threshold })

    if (!result.safe && enforce) {
      const reason = guard.locale === 'zh'
        ? `检测到可能的提示词注入攻击!\n风险评分: ${result.score}/100\n匹配规则: ${result.matched.map(m => m.name).join(', ')}`
        : `Potential prompt injection detected!\nRisk score: ${result.score}/100\nMatched: ${result.matched.map(m => m.name).join(', ')}`
      return { block: true, blockReason: `⚠️ [ShellWard] ${reason}` }
    }
  }, { name: 'shellward.input-auditor', priority: 300 })

  // Message scanning: register ALL known naming conventions
  // OpenClaw silently ignores unknown hooks (no error thrown), so register all variants
  const messageHandler = (event: any) => {
    const content = typeof event.content === 'string' ? event.content : ''
    if (!content) return
    guard.checkInjection(content, { source: 'message' })
  }

  api.on('message_received', messageHandler, { name: 'shellward.message-auditor', priority: 100 })
  api.on('message:received', messageHandler, { name: 'shellward.message-auditor-v2', priority: 100 })

  api.logger.info(`[ShellWard] L4 Input Auditor enabled`)
}
