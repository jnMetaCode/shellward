// src/layers/output-scanner.ts — L2: Redact PII & secrets from tool output via tool_result_persist hook

import { redactSensitive } from '../rules/sensitive-patterns'
import { resolveLocale } from '../types'
import type { ClawGuardConfig } from '../types'
import type { AuditLog } from '../audit-log'

export function setupOutputScanner(
  api: any,
  config: ClawGuardConfig,
  log: AuditLog,
  enforce: boolean,
) {
  const locale = resolveLocale(config)

  // tool_result_persist is SYNCHRONOUS — no async allowed
  api.on('tool_result_persist', (event: any) => {
    const content = event.result
    if (!content || typeof content !== 'string') return undefined

    const [redacted, findings] = redactSensitive(content)

    if (findings.length === 0) return undefined

    // Log each finding
    for (const f of findings) {
      log.write({
        level: 'HIGH',
        layer: 'L2',
        action: enforce ? 'redact' : 'detect',
        detail: `${f.name}: ${f.count} occurrence(s)`,
        tool: event.toolName,
        pattern: f.id,
      })
    }

    if (!enforce) return undefined

    // Build summary
    const summary = findings.map(f => `${f.name}(${f.count})`).join(', ')
    const notice = locale === 'zh'
      ? `\n\n⚠️ [ClawGuard] 已自动脱敏: ${summary}`
      : `\n\n⚠️ [ClawGuard] Auto-redacted: ${summary}`

    return { message: redacted + notice }
  }, { name: 'clawguard.output-scanner', priority: 100 })

  api.logger.info('[ClawGuard] L2 Output Scanner enabled')
}
