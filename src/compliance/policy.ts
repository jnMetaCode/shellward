// src/compliance/policy.ts — policy-as-code 门禁（响应 GitHub issue #2）
//
// 在 Git/CI 边界用声明式策略约束扫描结果：项目根放 `.shellward.json`，
// CI（shellward scan --ci）据此判定通过/失败。把"策略在 push 时声明 → 运行时执行"
// 的纵深防御补上 push 这一端。无策略文件时回退到默认（有 critical 即失败）。
//
// 示例 .shellward.json：
//   {
//     "failOn": ["secret", "pii"],        // 命中这些"类别"或"严重度"即失败
//     "maxFindings": 0,                     // 总发现数上限
//     "allowOverseas": ["OpenAI"]          // 允许的境外厂商（不计入失败）
//   }

import { readFileSync } from 'fs'
import { join } from 'path'
import type { ProjectScanResult, ProjectFinding, FindingKind } from './project-scan.js'

export interface ShellwardPolicy {
  /** 命中即失败：可填类别(secret/pii/overseas/env-perm) 或 严重度(critical/high/medium) */
  failOn?: string[]
  /** 总发现数上限（含被 allowOverseas 豁免后的） */
  maxFindings?: number
  /** 允许的境外大模型厂商（provider 名，命中这些的 overseas 发现被豁免） */
  allowOverseas?: string[]
}

export interface PolicyResult {
  pass: boolean
  source: 'file' | 'default'
  violations: string[]
  policy: ShellwardPolicy
}

const KINDS: FindingKind[] = ['overseas', 'secret', 'pii', 'env-perm']
const SEVERITIES = ['critical', 'high', 'medium']

/** 读取项目根的 .shellward.json；无/坏则返回默认策略（有 critical 即失败） */
export function loadPolicy(root: string): { policy: ShellwardPolicy; source: 'file' | 'default' } {
  try {
    const raw = readFileSync(join(root, '.shellward.json'), 'utf-8')
    const p = JSON.parse(raw)
    if (p && typeof p === 'object') return { policy: sanitize(p), source: 'file' }
  } catch { /* 无策略文件或解析失败 → 默认 */ }
  return { policy: { failOn: ['critical'] }, source: 'default' }
}

function sanitize(p: any): ShellwardPolicy {
  const out: ShellwardPolicy = {}
  if (Array.isArray(p.failOn)) out.failOn = p.failOn.filter((x: any) => typeof x === 'string')
  if (typeof p.maxFindings === 'number' && p.maxFindings >= 0) out.maxFindings = Math.floor(p.maxFindings)
  if (Array.isArray(p.allowOverseas)) out.allowOverseas = p.allowOverseas.filter((x: any) => typeof x === 'string')
  return out
}

/** 把被 allowOverseas 豁免的 overseas 发现去掉 */
function effective(findings: ProjectFinding[], allow: string[]): ProjectFinding[] {
  if (!allow.length) return findings
  const allowLower = new Set(allow.map(a => a.toLowerCase()))
  return findings.filter(f => {
    if (f.kind !== 'overseas') return true
    const prov = (f.provider_en || f.provider_zh || '').toLowerCase()
    return !allowLower.has(prov)
  })
}

/** 根据策略评估扫描结果，返回是否通过 + 违规说明 */
export function evaluatePolicy(scan: ProjectScanResult, policy: ShellwardPolicy): PolicyResult {
  const allow = policy.allowOverseas || []
  const findings = effective(scan.findings, allow)
  const violations: string[] = []

  const failOn = policy.failOn || []
  for (const token of failOn) {
    if (KINDS.includes(token as FindingKind)) {
      const n = findings.filter(f => f.kind === token).length
      if (n > 0) violations.push(`failOn "${token}": 命中 ${n} 项`)
    } else if (SEVERITIES.includes(token)) {
      const n = findings.filter(f => f.severity === token).length
      if (n > 0) violations.push(`failOn 严重度 "${token}": 命中 ${n} 项`)
    }
  }

  if (typeof policy.maxFindings === 'number' && findings.length > policy.maxFindings) {
    violations.push(`发现数 ${findings.length} 超过上限 maxFindings=${policy.maxFindings}`)
  }

  return { pass: violations.length === 0, source: 'default', violations, policy }
}

/** 加载 + 评估的便捷封装 */
export function checkPolicy(scan: ProjectScanResult, root: string): PolicyResult {
  const { policy, source } = loadPolicy(root)
  const r = evaluatePolicy(scan, policy)
  r.source = source
  return r
}
