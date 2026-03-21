// src/layers/tool-blocker.ts — L3 OpenClaw Adapter
// Thin adapter: wires OpenClaw's before_tool_call hook to ShellWard core engine

import type { ShellWard } from '../core/engine.js'

export function setupToolBlocker(api: any, guard: ShellWard, enforce: boolean) {
  api.on('before_tool_call', (event: any) => {
    const tool = String(event.toolName || '')
    const args: Record<string, any> = (event.params && typeof event.params === 'object') ? event.params : {}

    const toolCheck = guard.checkTool(tool)
    if (!toolCheck.allowed && enforce) {
      return { block: true, blockReason: `🚫 [ShellWard] ${toolCheck.reason}` }
    }

    if (guard.isExecTool(tool)) {
      const cmd = String(args.command ?? args.cmd ?? '')
      const cmdCheck = guard.checkCommand(cmd, tool)
      if (!cmdCheck.allowed && enforce) {
        return { block: true, blockReason: `🚫 [ShellWard] ${cmdCheck.reason}` }
      }
    }

    const rawPath = String(args.path || args.file_path || args.filename || args.target || '')
    if (rawPath && guard.isWriteOrDeleteTool(tool)) {
      const op = /delete|remove/i.test(tool) ? 'delete' as const : 'write' as const
      const pathCheck = guard.checkPath(rawPath, op, tool)
      if (!pathCheck.allowed && enforce) {
        return { block: true, blockReason: `🚫 [ShellWard] ${pathCheck.reason}` }
      }
    }
  }, { name: 'shellward.tool-blocker', priority: 200 })

  api.logger.info('[ShellWard] L3 Tool Blocker enabled')
}
