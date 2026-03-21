// src/layers/outbound-guard.ts — L6 OpenClaw Adapter
// Thin adapter: wires OpenClaw hooks to ShellWard core engine for outbound response scanning
// Compat: registers all known hook name variants

import type { ShellWard } from '../core/engine.js'

export function setupOutboundGuard(api: any, guard: ShellWard, enforce: boolean) {
  const handler = (event: any) => {
    const content = event.content
    if (!content || typeof content !== 'string') return undefined

    const result = guard.checkResponse(content)

    if (result.canaryLeak && enforce) {
      const warning = guard.locale === 'zh'
        ? '⚠️ [ShellWard] 检测到安全异常，本次回复已被拦截。可能存在提示词注入攻击。'
        : '⚠️ [ShellWard] Security anomaly detected, this response was blocked. Possible prompt injection attack.'
      return { content: warning }
    }

    return undefined
  }

  // Register ALL known naming conventions — OpenClaw silently ignores unknown ones
  api.on('message_sending', handler, { name: 'shellward.outbound-guard', priority: 100 })
  api.on('message:sent', handler, { name: 'shellward.outbound-guard-v2', priority: 100 })

  api.logger.info('[ShellWard] L6 Outbound Guard enabled')
}
