// src/layers/output-scanner.ts — L2: Redact PII & secrets from tool output via tool_result_persist hook
//
// event.message is a ToolResultMessage:
//   { role: 'toolResult', toolCallId, toolName, content: [{type:'text',text},...], details, isError, timestamp }
// Return { message: modifiedToolResultMessage } to replace, or undefined to keep original.

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
    const msg = event.message
    if (!msg || !Array.isArray(msg.content)) return undefined

    // Extract all text content and check for sensitive data
    let hasFindings = false
    const allFindings: { id: string; name: string; count: number }[] = []
    const redactedContent: any[] = []

    for (const block of msg.content) {
      if (block.type === 'text' && typeof block.text === 'string') {
        const [redacted, findings] = redactSensitive(block.text)
        if (findings.length > 0) {
          hasFindings = true
          for (const f of findings) {
            // Merge findings (same id → add counts)
            const existing = allFindings.find(e => e.id === f.id)
            if (existing) {
              existing.count += f.count
            } else {
              allFindings.push({ ...f })
            }
          }
          redactedContent.push({ type: 'text', text: redacted })
        } else {
          redactedContent.push(block)
        }
      } else {
        // Keep non-text blocks (images, etc.) as-is
        redactedContent.push(block)
      }
    }

    if (!hasFindings) return undefined

    // Log each finding
    for (const f of allFindings) {
      log.write({
        level: 'HIGH',
        layer: 'L2',
        action: enforce ? 'redact' : 'detect',
        detail: `${f.name}: ${f.count} occurrence(s)`,
        tool: msg.toolName,
        pattern: f.id,
      })
    }

    if (!enforce) return undefined

    // Append redaction notice
    const summary = allFindings.map(f => `${f.name}(${f.count})`).join(', ')
    const notice = locale === 'zh'
      ? `\n\n⚠️ [ClawGuard] 已自动脱敏: ${summary}`
      : `\n\n⚠️ [ClawGuard] Auto-redacted: ${summary}`

    // Add notice to last text block, or append a new one
    const lastText = redactedContent.findLast((b: any) => b.type === 'text')
    if (lastText) {
      lastText.text += notice
    } else {
      redactedContent.push({ type: 'text', text: notice })
    }

    // Return modified message with all original fields preserved
    return {
      message: {
        ...msg,
        content: redactedContent,
      },
    }
  }, { name: 'clawguard.output-scanner', priority: 100 })

  api.logger.info('[ClawGuard] L2 Output Scanner enabled')
}
