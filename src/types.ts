// src/types.ts — ShellWard type definitions

export interface ShellWardConfig {
  mode: 'enforce' | 'audit'
  locale: 'auto' | 'zh' | 'en'
  layers: {
    promptGuard: boolean
    outputScanner: boolean
    toolBlocker: boolean
    inputAuditor: boolean
    securityGate: boolean
    outboundGuard: boolean
    dataFlowGuard: boolean
    sessionGuard: boolean
  }
  injectionThreshold: number
}

export type ResolvedLocale = 'zh' | 'en'

export interface AuditEntry {
  ts: string
  level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  layer: 'L0' | 'L1' | 'L2' | 'L3' | 'L4' | 'L5' | 'L6' | 'L7' | 'L8'
  action: 'block' | 'redact' | 'detect' | 'allow' | 'inject' | 'error'
  detail: string
  tool?: string
  pattern?: string
  mode: 'enforce' | 'audit'
  [key: string]: unknown
}

export interface NamedPattern {
  name: string
  pattern: RegExp
  validate?: (match: string) => boolean
}

export interface ScanMatch {
  name: string
  preview: string
}

export interface DangerousCommandRule {
  id: string
  pattern: RegExp
  description_zh: string
  description_en: string
}

export interface ProtectedPathRule {
  id: string
  pattern: RegExp
  description_zh: string
  description_en: string
}

export interface InjectionRule {
  id: string
  name: string
  pattern: string
  flags?: string
  riskScore: number
  category: string
}

export const DEFAULT_CONFIG: ShellWardConfig = {
  mode: 'enforce',
  locale: 'auto',
  layers: {
    promptGuard: true,
    outputScanner: true,
    toolBlocker: true,
    inputAuditor: true,
    securityGate: true,
    outboundGuard: true,
    dataFlowGuard: true,
    sessionGuard: true,
  },
  injectionThreshold: 60,
}

/**
 * Detect locale from system environment.
 * Returns 'zh' if LANG/LC_ALL contains 'zh', otherwise 'en'.
 */
export function resolveLocale(config: ShellWardConfig): ResolvedLocale {
  if (config.locale === 'zh') return 'zh'
  if (config.locale === 'en') return 'en'
  // auto detection
  const lang = process.env.LANG || process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANGUAGE || ''
  return /\bzh[_-]|chinese/i.test(lang) ? 'zh' : 'en'
}
