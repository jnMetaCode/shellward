// src/layers/output-scanner.ts — L2 OpenClaw Adapter
// Thin adapter: wires OpenClaw's tool_result_persist hook to ShellWard core engine

import type { ShellWard } from '../core/engine.js'

export function setupOutputScanner(api: any, guard: ShellWard) {
  api.on('tool_result_persist', (event: any) => {
    const msg = event.message
    if (!msg || !Array.isArray(msg.content)) return undefined

    for (const block of msg.content) {
      if (block.type === 'text' && typeof block.text === 'string') {
        guard.scanData(block.text, msg.toolName)
      }
    }

    return undefined
  }, { name: 'shellward.output-scanner', priority: 100 })

  api.logger.info('[ShellWard] L2 Output Scanner enabled')
}
