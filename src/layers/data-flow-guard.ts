// src/layers/data-flow-guard.ts — L7 OpenClaw Adapter
// Thin adapter: wires OpenClaw hooks to ShellWard core engine for data flow tracking

import type { ShellWard } from '../core/engine.js'

export function setupDataFlowGuard(api: any, guard: ShellWard, enforce: boolean) {
  // Track file reads via after_tool_call
  api.on('after_tool_call', (event: any) => {
    const toolName = String(event.toolName || '').toLowerCase()
    const params = (event.params && typeof event.params === 'object') ? event.params : {}
    const path = String(params.path || params.file_path || params.filename || params.target || '')

    if (guard.isReadTool(toolName) && path) {
      guard.trackFileRead(event.toolName, path)
    }
  }, { name: 'shellward.data-flow-read-tracker', priority: 50 })

  // Block outbound sends when sensitive data was recently accessed
  api.on('before_tool_call', (event: any) => {
    const toolName = String(event.toolName || '')
    const params = (event.params && typeof event.params === 'object') ? event.params : {}

    const result = guard.checkOutbound(toolName, params)
    if (!result.allowed && enforce) {
      return { block: true, blockReason: `🚫 [ShellWard] ${result.reason}` }
    }
  }, { name: 'shellward.data-flow-egress', priority: 250 })

  api.logger.info('[ShellWard] L7 Data Flow Guard enabled')
}
