// src/compliance/policy.ts — policy-as-code 门禁（响应 GitHub issue #2 / #5）
//
// 在 Git/CI 边界用声明式策略约束扫描结果：项目根放 `.shellward.json`，
// CI（shellward scan --ci）据此判定通过/失败。把"策略在 push 时声明 → 运行时执行"
// 的纵深防御补上 push 这一端。无策略文件时回退到默认（有 critical 即失败）。
//
// 示例 .shellward.json：
//   {
//     "version": 1,
//     "failOn": ["secret", "pii"],        // 命中这些"类别"或"严重度"即失败
//     "maxFindings": 0,                     // 总发现数上限
//     "allowOverseas": ["OpenAI"],         // 允许的境外厂商（不计入失败）
//     "rules": [                            // 按路径的规则（issue #5），在全局规则之外叠加
//       { "path": "agents/**", "failOn": ["overseas"] }
//     ]
//   }
//
// 路径匹配（相对项目根，`/` 分隔）：
//   `**` 跨目录任意层级；`*` 目录内任意字符；`?` 单个字符
//   不含 `/` 的模式（如 `*.py`）匹配任意层级的文件名（同 .gitignore）
//   不含通配符的模式（如 `agents`）匹配该文件本身或该目录下的一切

import { readFileSync } from 'fs'
import { join } from 'path'
import type { ProjectScanResult, ProjectFinding, FindingKind } from './project-scan.js'

export interface PathRule {
  /** 路径模式，可填一个或多个（任一命中即在该规则范围内） */
  path: string | string[]
  /** 范围内命中即失败：类别或严重度 */
  failOn?: string[]
  /** 范围内发现数上限 */
  maxFindings?: number
  /** 范围内允许的境外厂商；不填则继承全局 allowOverseas，填了则覆盖（可填 [] 取消豁免） */
  allowOverseas?: string[]
}

export interface ShellwardPolicy {
  /** 策略格式版本（当前为 1），便于以后向前兼容 */
  version?: number
  /** 命中即失败：可填类别(secret/pii/overseas/env-perm) 或 严重度(critical/high/medium) */
  failOn?: string[]
  /** 总发现数上限（含被 allowOverseas 豁免后的） */
  maxFindings?: number
  /** 允许的境外大模型厂商（provider 名，命中这些的 overseas 发现被豁免） */
  allowOverseas?: string[]
  /** 按路径的规则：只对 file 命中 path 的发现生效，与全局规则同时检查 */
  rules?: PathRule[]
}

export interface PolicyResult {
  pass: boolean
  source: 'file' | 'default'
  violations: string[]
  /** 策略本身的问题（未知字段、拼错的 failOn 等）——不导致失败，但必须让人看见 */
  warnings: string[]
  policy: ShellwardPolicy
}

export const POLICY_VERSION = 1
const KINDS: FindingKind[] = ['overseas', 'secret', 'pii', 'env-perm']
const SEVERITIES = ['critical', 'high', 'medium']
const TOP_KEYS = new Set(['$schema', 'version', 'failOn', 'maxFindings', 'allowOverseas', 'rules'])
const RULE_KEYS = new Set(['path', 'failOn', 'maxFindings', 'allowOverseas'])

/** 读取项目根的 .shellward.json；无/坏则返回默认策略（有 critical 即失败） */
export function loadPolicy(root: string): { policy: ShellwardPolicy; source: 'file' | 'default'; warnings: string[] } {
  let raw: string
  try {
    raw = readFileSync(join(root, '.shellward.json'), 'utf-8')
  } catch {
    return { policy: { failOn: ['critical'] }, source: 'default', warnings: [] }
  }
  try {
    const p = JSON.parse(raw)
    if (p && typeof p === 'object' && !Array.isArray(p)) {
      const warnings: string[] = []
      return { policy: sanitize(p, warnings), source: 'file', warnings }
    }
  } catch { /* 解析失败 → 默认 */ }
  return {
    policy: { failOn: ['critical'] },
    source: 'default',
    warnings: ['.shellward.json 不是合法的 JSON 对象，已回退默认策略（有 critical 即失败）'],
  }
}

function strArray(v: any): string[] | undefined {
  return Array.isArray(v) ? v.filter((x: any) => typeof x === 'string') : undefined
}

function checkFailOn(tokens: string[] | undefined, where: string, warnings: string[]): void {
  for (const t of tokens || []) {
    if (!KINDS.includes(t as FindingKind) && !SEVERITIES.includes(t)) {
      warnings.push(`${where}failOn 含未知值 "${t}"（可选：${[...KINDS, ...SEVERITIES].join(' / ')}），已忽略`)
    }
  }
}

function sanitize(p: any, warnings: string[]): ShellwardPolicy {
  const out: ShellwardPolicy = {}
  for (const k of Object.keys(p)) if (!TOP_KEYS.has(k)) warnings.push(`未知字段 "${k}"，已忽略`)

  if (typeof p.version === 'number') {
    out.version = p.version
    if (p.version > POLICY_VERSION) warnings.push(`策略 version=${p.version} 高于本版本支持的 ${POLICY_VERSION}，未识别的部分将被忽略——请升级 shellward`)
  }
  out.failOn = strArray(p.failOn)
  if (!out.failOn) delete out.failOn
  checkFailOn(out.failOn, '', warnings)
  if (typeof p.maxFindings === 'number' && p.maxFindings >= 0) out.maxFindings = Math.floor(p.maxFindings)
  const allow = strArray(p.allowOverseas)
  if (allow) out.allowOverseas = allow

  if (p.rules !== undefined) {
    if (!Array.isArray(p.rules)) {
      warnings.push('rules 应为数组，已忽略')
    } else {
      const rules: PathRule[] = []
      p.rules.forEach((r: any, i: number) => {
        const where = `rules[${i}] `
        if (!r || typeof r !== 'object') { warnings.push(`${where}不是对象，已忽略`); return }
        for (const k of Object.keys(r)) if (!RULE_KEYS.has(k)) warnings.push(`${where}未知字段 "${k}"，已忽略`)
        const paths = typeof r.path === 'string' ? [r.path] : strArray(r.path)
        if (!paths || paths.length === 0 || paths.some(s => !s.trim())) {
          warnings.push(`${where}缺少有效的 path，整条规则已忽略`)
          return
        }
        const rule: PathRule = { path: typeof r.path === 'string' ? r.path : paths }
        const fo = strArray(r.failOn)
        if (fo) { rule.failOn = fo; checkFailOn(fo, where, warnings) }
        if (typeof r.maxFindings === 'number' && r.maxFindings >= 0) rule.maxFindings = Math.floor(r.maxFindings)
        const ao = strArray(r.allowOverseas)
        if (ao) rule.allowOverseas = ao
        if (!rule.failOn && rule.maxFindings === undefined) warnings.push(`${where}既没有 failOn 也没有 maxFindings，不会产生任何约束`)
        rules.push(rule)
      })
      out.rules = rules
    }
  }
  return out
}

/** 统一成相对、`/` 分隔的路径 */
function normPath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '')
}

/** 单段通配（`*` / `?`，不跨 `/`）：经典双指针回退，O(n·m)，不会回溯爆炸 */
function matchSegment(str: string, pat: string): boolean {
  let s = 0, p = 0, star = -1, mark = 0
  while (s < str.length) {
    if (p < pat.length && (pat[p] === '?' || pat[p] === str[s])) { s++; p++ }
    else if (p < pat.length && pat[p] === '*') { star = p++; mark = s }
    else if (star >= 0) { p = star + 1; s = ++mark }
    else return false
  }
  while (p < pat.length && pat[p] === '*') p++
  return p === pat.length
}

/** 分段匹配，`**` 段可吃掉 0..n 段；用 DP 而非正则，最坏 O(段数²·段长) */
function matchSegments(file: string[], pat: string[]): boolean {
  // ok[j] = pat[i..] 能否匹配 file[j..]，自后向前滚动
  let next: boolean[] = new Array(file.length + 1).fill(false)
  next[file.length] = true
  for (let i = pat.length - 1; i >= 0; i--) {
    const cur: boolean[] = new Array(file.length + 1).fill(false)
    for (let j = file.length; j >= 0; j--) {
      if (pat[i] === '**') cur[j] = next[j] || (j < file.length && cur[j + 1])
      else cur[j] = j < file.length && next[j + 1] && matchSegment(file[j], pat[i])
    }
    next = cur
  }
  return next[0]
}

/** 判断相对路径是否命中 glob 模式（导出供测试） */
export function matchPath(file: string, pattern: string): boolean {
  let g = normPath(pattern.trim())
  if (!g) return false
  if (g.endsWith('/')) g += '**'
  const hasGlob = /[*?]/.test(g)
  const segs = g.split('/').filter(Boolean).map(x => (/^\*{2,}$/.test(x) ? '**' : x))
  // 连续的 ** 等价于一个
  const pat = segs.filter((x, i) => !(x === '**' && segs[i - 1] === '**'))
  if (!g.includes('/')) pat.unshift('**') // 不含 `/`：任意层级（同 .gitignore）
  if (!hasGlob) pat.push('**') // 无通配：该文件本身或其目录下一切
  return matchSegments(normPath(file).split('/').filter(Boolean), pat)
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

/** 在一组发现上检查 failOn / maxFindings，违规说明加上前缀 */
function checkScope(findings: ProjectFinding[], failOn: string[], maxFindings: number | undefined, prefix: string, out: string[]): void {
  for (const token of failOn) {
    if (KINDS.includes(token as FindingKind)) {
      const hit = findings.filter(f => f.kind === token)
      if (hit.length > 0) out.push(`${prefix}failOn "${token}": 命中 ${hit.length} 项${sample(hit)}`)
    } else if (SEVERITIES.includes(token)) {
      const hit = findings.filter(f => f.severity === token)
      if (hit.length > 0) out.push(`${prefix}failOn 严重度 "${token}": 命中 ${hit.length} 项${sample(hit)}`)
    }
  }
  if (typeof maxFindings === 'number' && findings.length > maxFindings) {
    out.push(`${prefix}发现数 ${findings.length} 超过上限 maxFindings=${maxFindings}`)
  }
}

/** 列出前几个命中位置，CI 日志里直接能定位 */
function sample(hit: ProjectFinding[]): string {
  const locs = hit.slice(0, 3).map(f => f.line ? `${normPath(f.file)}:${f.line}` : normPath(f.file))
  return `（${locs.join(', ')}${hit.length > 3 ? ' …' : ''}）`
}

/** 根据策略评估扫描结果，返回是否通过 + 违规说明 */
export function evaluatePolicy(scan: ProjectScanResult, policy: ShellwardPolicy): PolicyResult {
  const globalAllow = policy.allowOverseas || []
  const violations: string[] = []

  checkScope(effective(scan.findings, globalAllow), policy.failOn || [], policy.maxFindings, '', violations)

  for (const rule of policy.rules || []) {
    const patterns = Array.isArray(rule.path) ? rule.path : [rule.path]
    const inScope = scan.findings.filter(f => patterns.some(p => matchPath(f.file, p)))
    const scoped = effective(inScope, rule.allowOverseas ?? globalAllow)
    checkScope(scoped, rule.failOn || [], rule.maxFindings, `[${patterns.join(', ')}] `, violations)
  }

  return { pass: violations.length === 0, source: 'default', violations, warnings: [], policy }
}

/** 加载 + 评估的便捷封装 */
export function checkPolicy(scan: ProjectScanResult, root: string): PolicyResult {
  const { policy, source, warnings } = loadPolicy(root)
  const r = evaluatePolicy(scan, policy)
  r.source = source
  r.warnings = warnings
  return r
}
