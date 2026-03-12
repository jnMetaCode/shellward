// src/layers/input-auditor.ts — L4: Injection detection + message audit via before_tool_call + message_received

import { INJECTION_RULES_ZH } from '../rules/injection-zh'
import { INJECTION_RULES_EN } from '../rules/injection-en'
import { resolveLocale } from '../types'
import type { ShellWardConfig, InjectionRule, ResolvedLocale } from '../types'
import type { AuditLog } from '../audit-log'

interface CompiledRule extends InjectionRule {
  compiled: RegExp
}

// Text fields to extract from tool arguments for scanning
const TEXT_FIELDS = [
  'content', 'body', 'text', 'message', 'query',
  'command', 'code', 'html', 'url', 'prompt',
  'subject', 'description', 'input',
]

// Hidden/invisible Unicode character ranges
const HIDDEN_CHAR_RANGES: [number, number, string][] = [
  [0x200B, 0x200F, 'Zero-width/Direction'],
  [0x2028, 0x2029, 'Line/Paragraph separator'],
  [0x202A, 0x202E, 'Bidi control'],
  [0x2060, 0x2064, 'Invisible operators'],
  [0xFEFF, 0xFEFF, 'BOM/Zero-width no-break'],
  [0x00AD, 0x00AD, 'Soft hyphen'],
  [0xFFF9, 0xFFFB, 'Interlinear annotation'],
]

export function setupInputAuditor(
  api: any,
  config: ShellWardConfig,
  log: AuditLog,
  enforce: boolean,
) {
  const locale = resolveLocale(config)
  const allRules = [...INJECTION_RULES_ZH, ...INJECTION_RULES_EN]
  const compiled: CompiledRule[] = allRules.map(rule => ({
    ...rule,
    compiled: new RegExp(rule.pattern, rule.flags || 'i'),
  }))

  // Hook 1: Check tool call arguments for injection
  api.on('before_tool_call', (event: any) => {
    const args: Record<string, any> = (event.params && typeof event.params === 'object') ? event.params : {}
    const texts = extractTexts(args)
    if (texts.length === 0) return

    const fullText = texts.join('\n')
    return checkInjection(fullText, event.toolName, locale, compiled, config, log, enforce)
  }, { name: 'shellward.input-auditor', priority: 300 })

  // Hook 2: Audit inbound messages
  api.on('message_received', (event: any) => {
    const content = typeof event.content === 'string' ? event.content : ''
    if (!content) return

    // Detect hidden characters
    const hidden = detectHiddenChars(content)
    if (hidden.length > 0) {
      log.write({
        level: 'MEDIUM',
        layer: 'L4',
        action: 'detect',
        detail: `Hidden characters detected in message: ${hidden.map(h => h.name).join(', ')} (${hidden.length} chars)`,
      })
    }

    // Check for injection patterns (log only, don't block messages)
    const { score, matched } = scoreText(content, compiled)
    if (score >= config.injectionThreshold) {
      log.write({
        level: score >= 80 ? 'CRITICAL' : 'HIGH',
        layer: 'L4',
        action: 'detect',
        detail: locale === 'zh'
          ? `消息中检测到注入模式 (评分: ${score}): ${matched.map(m => m.name).join(', ')}`
          : `Injection patterns in message (score: ${score}): ${matched.map(m => m.name).join(', ')}`,
      })
    }
  }, { name: 'shellward.message-auditor', priority: 100 })

  api.logger.info(`[ShellWard] L4 Input Auditor enabled (${compiled.length} injection rules)`)
}

function checkInjection(
  text: string,
  tool: string,
  locale: ResolvedLocale,
  rules: CompiledRule[],
  config: ShellWardConfig,
  log: AuditLog,
  enforce: boolean,
): { block: true; blockReason: string } | undefined {
  // Hidden char detection
  const hidden = detectHiddenChars(text)
  if (hidden.length > 0) {
    log.write({
      level: 'MEDIUM',
      layer: 'L4',
      action: 'detect',
      detail: `Hidden chars in tool args: ${hidden.map(h => h.name).join(', ')}`,
      tool,
    })
  }

  // Score injection rules
  let { score, matched } = scoreText(text, rules)

  // Bonus for hidden chars (potential obfuscation)
  if (hidden.length > 3) {
    score += 20
  }

  if (score < config.injectionThreshold) return

  const reason = locale === 'zh'
    ? `检测到可能的提示词注入攻击!\n风险评分: ${score}/100\n匹配规则: ${matched.map(m => m.name).join(', ')}`
    : `Potential prompt injection detected!\nRisk score: ${score}/100\nMatched: ${matched.map(m => m.name).join(', ')}`

  log.write({
    level: score >= 80 ? 'CRITICAL' : 'HIGH',
    layer: 'L4',
    action: enforce ? 'block' : 'detect',
    detail: reason,
    tool,
  })

  if (enforce) {
    return { block: true, blockReason: `⚠️ [ShellWard] ${reason}` }
  }
}

function scoreText(text: string, rules: CompiledRule[]): { score: number; matched: { id: string; name: string; score: number }[] } {
  let score = 0
  const matched: { id: string; name: string; score: number }[] = []

  for (const rule of rules) {
    if (rule.compiled.test(text)) {
      score += rule.riskScore
      matched.push({ id: rule.id, name: rule.name, score: rule.riskScore })
    }
  }

  return { score, matched }
}

function extractTexts(args: Record<string, any>): string[] {
  const results: string[] = []
  for (const field of TEXT_FIELDS) {
    if (typeof args[field] === 'string' && args[field].length > 0) {
      results.push(args[field])
    }
  }
  return results
}

function detectHiddenChars(text: string): { char: string; codePoint: number; name: string }[] {
  const found: { char: string; codePoint: number; name: string }[] = []
  for (const char of text) {
    const cp = char.codePointAt(0)!
    for (const [start, end, name] of HIDDEN_CHAR_RANGES) {
      if (cp >= start && cp <= end) {
        found.push({ char, codePoint: cp, name })
        break
      }
    }
  }
  return found
}
