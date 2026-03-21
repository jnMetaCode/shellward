// src/rules/sensitive-patterns.ts — PII & secret patterns for output redaction (global + China)

import type { NamedPattern, ScanMatch } from '../types.js'

export interface SensitivePattern {
  id: string
  name: string
  regex: RegExp
  replacement: string
  validate?: (match: string) => boolean
}

export const SENSITIVE_PATTERNS: SensitivePattern[] = [
  // ===== API Keys & Tokens =====
  {
    id: 'openai_key',
    name: 'OpenAI API Key',
    regex: /sk-[a-zA-Z0-9]{20,}/g,
    replacement: '[REDACTED:OpenAI Key]',
  },
  {
    id: 'anthropic_key',
    name: 'Anthropic Key',
    regex: /sk-ant-[a-zA-Z0-9\-]{20,}/g,
    replacement: '[REDACTED:Anthropic Key]',
  },
  {
    id: 'aws_access',
    name: 'AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/g,
    replacement: '[REDACTED:AWS Key]',
  },
  {
    id: 'github_token',
    name: 'GitHub Token',
    regex: /gh[ps]_[A-Za-z0-9_]{36,}/g,
    replacement: '[REDACTED:GitHub Token]',
  },
  {
    id: 'generic_api_key',
    name: 'Generic API Key',
    regex: /(?:api[_-]?key|api[_-]?token|access[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?/gi,
    replacement: '[REDACTED:API Key]',
  },

  // ===== Private Keys & Secrets =====
  {
    id: 'private_key',
    name: 'Private Key',
    regex: /-----BEGIN\s(?:RSA|EC|OPENSSH|DSA|PGP)\sPRIVATE\sKEY-----/g,
    replacement: '[REDACTED:Private Key]',
  },
  {
    id: 'jwt',
    name: 'JWT Token',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    replacement: '[REDACTED:JWT]',
  },
  {
    id: 'password',
    name: 'Password',
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"]?\S{6,100}['"]?/gi,
    replacement: '[REDACTED:Password]',
  },
  {
    id: 'conn_string',
    name: 'Database Connection String',
    regex: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]{10,}/g,
    replacement: '[REDACTED:Connection String]',
  },

  // ===== Chinese PII (核心差异点) =====
  {
    id: 'id_card_cn',
    name: '身份证号 / CN ID Card',
    regex: /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g,
    replacement: '[REDACTED:身份证号]',
    validate: validateIdCardCN,
  },
  {
    id: 'phone_cn',
    name: '手机号 / CN Phone',
    regex: /(?<!\d)1[3-9]\d{9}(?!\d)/g,
    replacement: '[REDACTED:手机号]',
  },
  {
    id: 'bank_card_cn',
    name: '银行卡号 / CN Bank Card',
    regex: /(?<!\d)(?:62|4|5[1-5])\d{14,17}(?!\d)/g,
    replacement: '[REDACTED:银行卡号]',
    validate: validateLuhn,
  },

  // ===== International PII =====
  {
    id: 'email',
    name: 'Email Address',
    regex: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,10}/g,
    replacement: '[REDACTED:Email]',
  },
  {
    id: 'ssn_us',
    name: 'US SSN',
    // Exclude date-like patterns (YYYY-MM-DD) and ranges starting with 000/666/9xx
    regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    replacement: '[REDACTED:SSN]',
    validate: validateSSN,
  },
  {
    id: 'credit_card',
    name: 'Credit Card',
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
    replacement: '[REDACTED:Credit Card]',
    validate: validateLuhn,
  },
]

/**
 * Scan text and return matches (without modifying text).
 */
export function scanForSensitive(text: string): ScanMatch[] {
  const results: ScanMatch[] = []
  for (const pat of SENSITIVE_PATTERNS) {
    const regex = new RegExp(pat.regex.source, pat.regex.flags)
    let match: RegExpExecArray | null
    while ((match = regex.exec(text)) !== null) {
      if (pat.validate && !pat.validate(match[0])) continue
      results.push({
        name: pat.name,
        preview: match[0].slice(0, 8) + '***',
      })
    }
  }
  return results
}

/**
 * Redact all sensitive data in text. Returns [redactedText, findings[]]
 */
export function redactSensitive(text: string): [string, { id: string; name: string; count: number }[]] {
  let result = text
  const findings: { id: string; name: string; count: number }[] = []

  for (const pat of SENSITIVE_PATTERNS) {
    const regex = new RegExp(pat.regex.source, pat.regex.flags)
    let count = 0
    result = result.replace(regex, (match) => {
      if (pat.validate && !pat.validate(match)) return match
      count++
      return pat.replacement
    })
    if (count > 0) {
      findings.push({ id: pat.id, name: pat.name, count })
    }
  }

  return [result, findings]
}

// ===== Validators =====

function validateIdCardCN(id: string): boolean {
  if (id.length !== 18) return false
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
  const checkCodes = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
  let sum = 0
  for (let i = 0; i < 17; i++) {
    sum += parseInt(id[i]) * weights[i]
  }
  return checkCodes[sum % 11].toUpperCase() === id[17].toUpperCase()
}

/**
 * Validate US SSN: reject date-like patterns (YYYY-MM-DD)
 */
function validateSSN(ssn: string): boolean {
  const parts = ssn.split('-')
  if (parts.length !== 3) return false
  const [area, group, serial] = parts.map(Number)
  // Reject if it looks like a date (first part 1900-2099)
  if (area >= 1900 && area <= 2099 && group >= 1 && group <= 12) return false
  // Valid SSN ranges
  if (area < 1 || area > 899 || area === 666) return false
  if (group < 1 || group > 99) return false
  if (serial < 1 || serial > 9999) return false
  return true
}

function validateLuhn(num: string): boolean {
  const digits = num.replace(/\D/g, '')
  if (digits.length < 13) return false
  let sum = 0
  let alternate = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i])
    if (alternate) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
    alternate = !alternate
  }
  return sum % 10 === 0
}
