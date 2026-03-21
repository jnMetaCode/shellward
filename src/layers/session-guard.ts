// src/layers/session-guard.ts — L8 OpenClaw Adapter
// Thin adapter: wires OpenClaw hooks to ShellWard core engine for session monitoring
// Compat: registers all known hook name variants

import type { ShellWard } from '../core/engine.js'

export function setupSessionGuard(api: any, guard: ShellWard, enforce: boolean) {
  const sessionEndHandler = () => {
    guard.log.write({
      level: 'INFO',
      layer: 'L8',
      action: 'detect',
      detail: guard.locale === 'zh'
        ? '会话结束 — 安全审计完成'
        : 'Session ended — security audit complete',
    })
  }

  // Register ALL known naming conventions for session end
  api.on('session_end', sessionEndHandler, { name: 'shellward.session-end', priority: 50 })
  api.on('session:end', sessionEndHandler, { name: 'shellward.session-end-v2', priority: 50 })
  api.on('command:new', sessionEndHandler, { name: 'shellward.session-end-fallback', priority: 50 })

  const subagentHandler = (event: any) => {
    const mode = event.mode || 'unknown'
    guard.log.write({
      level: 'MEDIUM',
      layer: 'L8',
      action: 'detect',
      detail: guard.locale === 'zh'
        ? `子 Agent 创建: mode=${mode}, agentId=${event.agentId || 'unknown'}`
        : `Subagent spawning: mode=${mode}, agentId=${event.agentId || 'unknown'}`,
    })
  }

  // Register ALL known naming conventions for subagent monitoring
  api.on('subagent_spawning', subagentHandler, { name: 'shellward.subagent-guard', priority: 100 })
  api.on('subagent:spawning', subagentHandler, { name: 'shellward.subagent-guard-v2', priority: 100 })

  api.logger.info('[ShellWard] L8 Session Guard enabled')
}
