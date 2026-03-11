// src/types.ts — ClawGuard type definitions

export interface ClawGuardConfig {
  mode: 'enforce' | 'audit'
  locale: 'auto' | 'zh' | 'en'
  layers: {
    promptGuard: boolean
    outputScanner: boolean
    toolBlocker: boolean
    inputAuditor: boolean
    securityGate: boolean
  }
  injectionThreshold: number
}

export type ResolvedLocale = 'zh' | 'en'

export interface AuditEntry {
  ts: string
  level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  layer: 'L1' | 'L2' | 'L3' | 'L4' | 'L5'
  action: 'block' | 'redact' | 'detect' | 'allow' | 'inject'
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

export const DEFAULT_CONFIG: ClawGuardConfig = {
  mode: 'enforce',
  locale: 'auto',
  layers: {
    promptGuard: true,
    outputScanner: true,
    toolBlocker: true,
    inputAuditor: true,
    securityGate: true,
  },
  injectionThreshold: 60,
}

/**
 * Detect locale from system environment.
 * Returns 'zh' if LANG/LC_ALL contains 'zh', otherwise 'en'.
 */
export function resolveLocale(config: ClawGuardConfig): ResolvedLocale {
  if (config.locale === 'zh') return 'zh'
  if (config.locale === 'en') return 'en'
  // auto detection
  const lang = process.env.LANG || process.env.LANGUAGE || process.env.LC_ALL || ''
  return /zh/i.test(lang) ? 'zh' : 'en'
}
