// src/layers/prompt-guard.ts — L1 OpenClaw Adapter
// Thin adapter: wires OpenClaw's before_prompt_build hook to ShellWard core engine

import type { ShellWard } from '../core/engine.js'

export function setupPromptGuard(api: any, guard: ShellWard) {
  api.on('before_prompt_build', () => {
    guard.log.write({
      level: 'INFO',
      layer: 'L1',
      action: 'inject',
      detail: 'Security prompt injected',
    })
    return { prependSystemContext: guard.getSecurityPrompt() }
  }, { name: 'shellward.prompt-guard', priority: 100 })

  api.logger.info('[ShellWard] L1 Prompt Guard enabled')
}
