// src/compliance/audit.ts — 合规体检引擎
//
// 跑遍 COMPLIANCE_CONTROLS，对每个控制项给出 pass / warn / fail / manual，
// 汇总成红黄绿评分卡。这是「一键合规体检报告」(月1 获客钩子) 的核心。
//
// 设计为可注入 (EnvFacts)：测试可直接喂事实，运行时则从真实环境采集。

import { readFileSync, statSync } from 'fs'
import { join } from 'path'
import { getHomeDir } from '../utils.js'
import { detectOverseasLLM } from '../rules/overseas-llm.js'
import type { OverseasMatch } from '../rules/overseas-llm.js'
import { scanProject } from './project-scan.js'
import type { ProjectScanResult } from './project-scan.js'
import { COMPLIANCE_CONTROLS } from './regulations.js'
import type { ComplianceControl, Regulation, Severity } from './regulations.js'
import type { ShellWardConfig } from '../types.js'

const LOG_FILE = join(getHomeDir(), '.openclaw', 'shellward', 'audit.jsonl')
const SIX_MONTHS_MS = 182 * 24 * 60 * 60 * 1000

export type ControlStatus = 'pass' | 'warn' | 'fail' | 'manual'

export interface ControlResult {
  control: ComplianceControl
  status: ControlStatus
  detail_zh: string
  detail_en: string
}

export interface AuditLogFacts {
  exists: boolean
  entryCount: number
  /** 最早一条记录时间戳 (ISO)，用于判断是否覆盖 6 个月留存 */
  oldestTs?: string
  newestTs?: string
}

export interface EnvFacts {
  isRoot: boolean
  auditLog: AuditLogFacts
  /** 从环境/配置中探测到的境外大模型端点 */
  overseas: OverseasMatch[]
}

export interface ComplianceReport {
  /** 0-100 合规得分 */
  score: number
  /** 总评级 */
  grade: 'A' | 'B' | 'C' | 'D'
  passed: number
  warned: number
  failed: number
  manual: number
  total: number
  results: ControlResult[]
  generatedAt: string
  /** 项目实测风险造成的扣分（仅项目体检路径）；0 表示纯控制项评分 */
  projectPenalty?: number
  /** 是否为静态扫描（未部署运行时）：此时多数控制项不可验证，得分不代表完整合规 */
  staticScan?: boolean
  /** 项目扫描的文件总数（静态扫描路径） */
  filesScanned?: number
}

/** 层能力映射：控制项 id → 必须启用的层（全部启用才 pass，部分启用 warn，全关 fail） */
const CAPABILITY_LAYERS: Record<string, (keyof ShellWardConfig['layers'])[]> = {
  'csl-content-block': ['outputScanner', 'outboundGuard'],
  'csl-intrusion': ['inputAuditor', 'toolBlocker'],
  'pipl-spi-detect': ['outputScanner'],
  'pipl-minimize': ['dataFlowGuard'],
  'pipl-auto-decision': ['securityGate'],
  'mlps-access-control': ['securityGate'],
  'cbdt-redact-before-export': ['dataFlowGuard'],
}

/** 采集真实环境事实（运行时调用；测试可绕过直接注入 EnvFacts） */
export function gatherEnvFacts(): EnvFacts {
  // 1. root 检测
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0

  // 2. 审计日志事实
  const auditLog = readAuditLogFacts()

  // 3. 出境端点探测：扫描常见环境变量中的 base_url / 端点
  const overseas: OverseasMatch[] = []
  const seen = new Set<string>()
  for (const [k, v] of Object.entries(process.env)) {
    if (!v) continue
    if (!/(_BASE_URL|_API_BASE|_ENDPOINT|_URL|OPENAI|ANTHROPIC|GEMINI|LLM)/i.test(k)) continue
    const m = detectOverseasLLM(v)
    if (m.isOverseas && m.endpointId && !seen.has(m.endpointId)) {
      seen.add(m.endpointId)
      overseas.push(m)
    }
  }

  return { isRoot, auditLog, overseas }
}

function readAuditLogFacts(): AuditLogFacts {
  try {
    statSync(LOG_FILE)
    const content = readFileSync(LOG_FILE, 'utf-8')
    const lines = content.trim().split('\n').filter(Boolean)
    if (lines.length === 0) return { exists: true, entryCount: 0 }
    const firstTs = extractTs(lines[0])
    const lastTs = extractTs(lines[lines.length - 1])
    return { exists: true, entryCount: lines.length, oldestTs: firstTs, newestTs: lastTs }
  } catch {
    return { exists: false, entryCount: 0 }
  }
}

function extractTs(line: string): string | undefined {
  const m = line.match(/"ts":"([^"]+)"/)
  return m?.[1]
}

export interface AuditOptions {
  /**
   * ShellWard 是否作为运行时防护已部署。
   * - true（默认）：MCP / 插件上下文，能力层确实在运行，如实评估
   * - false：CLI 静态扫描，未部署运行时 —— 能力/审计类控制项标为顾问态，不虚报"已启用"
   */
  deployed?: boolean
}

/**
 * 运行合规体检。
 * @param config ShellWard 当前配置
 * @param facts  环境事实；不传则从真实环境采集
 * @param opts   评估上下文（是否已部署运行时）
 */
export function runComplianceAudit(config: ShellWardConfig, facts?: EnvFacts, opts?: AuditOptions): ComplianceReport {
  const env = facts ?? gatherEnvFacts()
  const deployed = opts?.deployed ?? true
  const results: ControlResult[] = COMPLIANCE_CONTROLS.map(c => checkControl(c, config, env, deployed))

  let passed = 0, warned = 0, failed = 0, manual = 0
  for (const r of results) {
    if (r.status === 'pass') passed++
    else if (r.status === 'warn') warned++
    else if (r.status === 'fail') failed++
    else manual++
  }

  const score = computeScore(results)
  return {
    score,
    grade: gradeOf(score),
    passed, warned, failed, manual,
    total: results.length,
    results,
    generatedAt: new Date().toISOString(),
  }
}

export interface ProjectComplianceResult {
  report: ComplianceReport
  scan: ProjectScanResult
}

/**
 * 面向真实项目的体检：扫描项目目录的真实风险，并入评分，再跑控制项体检。
 * 这是 CLI (`shellward scan`) 的入口 —— 报告关于「用户项目」而非「ShellWard 开关」。
 */
export function runProjectComplianceAudit(config: ShellWardConfig, root: string): ProjectComplianceResult {
  const scan = scanProject(root)
  const env = gatherEnvFacts()

  // 把文件中实测到的境外端点/依赖并入 facts（按 endpointId 或 provider 去重），
  // 使数据出境项基于真实证据（含 SDK 依赖通道）
  const seen = new Set(env.overseas.map(o => (o.endpointId || o.provider_en || '').toLowerCase()))
  for (const f of scan.findings) {
    if (f.kind !== 'overseas') continue
    // 按厂商去重（不区分大小写），避免"端点命中"与"SDK依赖命中"把同一厂商列两次
    const key = (f.provider_en || f.endpointId || '').toLowerCase()
    if (!key || seen.has(key)) continue
    seen.add(key)
    env.overseas.push({
      isOverseas: true,
      endpointId: f.endpointId,
      provider_zh: f.provider_zh,
      provider_en: f.provider_en,
    })
  }

  // CLI 静态扫描：未部署运行时 → 能力/审计类不虚报"已启用"，只如实评估项目证据
  const report = runComplianceAudit(config, env, { deployed: false })

  // 「敏感个人信息识别」这条静态扫描确实做得到 —— 直接连到扫描结果，不再标"待核验"
  const piiCount = scan.findings.filter(f => f.kind === 'pii').length
  const spi = report.results.find(r => r.control.id === 'pipl-spi-detect')
  if (spi) {
    if (piiCount > 0) {
      spi.status = 'fail'
      spi.detail_zh = `扫描在项目文件中发现 ${piiCount} 处个人信息暴露（见上方「项目实测风险」）— 需评估最小必要并脱敏`
      spi.detail_en = `Scan found ${piiCount} PII exposure(s) in files — assess minimization & de-identify`
    } else {
      spi.status = 'pass'
      spi.detail_zh = '已扫描项目文件，未发现明文个人信息暴露（运行时 PII 处理建议仍接入 ShellWard）'
      spi.detail_en = 'Scanned files; no plaintext PII exposure found'
    }
  }

  // override 改了状态 → 重算计数与控制项得分
  recount(report)
  const baseScore = computeScore(report.results)

  // 发现驱动评分：项目实测风险按严重度扣分（封顶 40），使分数反映"你的真实风险"
  const penalty = computeProjectPenalty(scan)
  report.score = Math.max(0, baseScore - penalty)
  report.grade = gradeOf(report.score)
  if (penalty > 0) report.projectPenalty = penalty
  report.staticScan = true
  report.filesScanned = scan.filesScanned

  return { report, scan }
}

/** 重新统计 pass/warn/fail/manual 计数（控制项状态被覆盖后调用） */
function recount(report: ComplianceReport): void {
  let passed = 0, warned = 0, failed = 0, manual = 0
  for (const r of report.results) {
    if (r.status === 'pass') passed++
    else if (r.status === 'warn') warned++
    else if (r.status === 'fail') failed++
    else manual++
  }
  report.passed = passed; report.warned = warned; report.failed = failed; report.manual = manual
}

const FINDING_PENALTY = { critical: 8, high: 4, medium: 1 } as const
const MAX_PROJECT_PENALTY = 40

function computeProjectPenalty(scan: ProjectScanResult): number {
  let p = 0
  for (const f of scan.findings) p += FINDING_PENALTY[f.severity]
  return Math.min(MAX_PROJECT_PENALTY, p)
}

function checkControl(c: ComplianceControl, config: ShellWardConfig, env: EnvFacts, deployed: boolean): ControlResult {
  // 静态扫描（未部署运行时）下，能力层/审计日志类控制项无法验证 —— 标为顾问态，绝不虚报"已合规"。
  // 「为何待核验」统一在报告区块开头说一次；这里每行只留"该做什么"，避免 12 行重复同一句。
  if (!deployed && (c.method === 'capability' || c.method === 'config' || c.method === 'audit')) {
    return mk(c, 'manual', c.remediation_zh, c.remediation_en)
  }
  switch (c.method) {
    case 'capability': return checkCapability(c, config)
    case 'config':     return checkConfig(c, config)
    case 'audit':      return checkAudit(c, env)
    case 'env':        return checkEnv(c, env)
    case 'manual':     return mk(c, 'manual',
      '需人工确认 / 路线图功能：' + c.remediation_zh,
      'Manual / roadmap: ' + c.remediation_en)
  }
}

function checkCapability(c: ComplianceControl, config: ShellWardConfig): ControlResult {
  const required = CAPABILITY_LAYERS[c.id]
  if (!required) {
    // 未显式映射的能力项：以 enforce 模式作为兜底信号
    return config.mode === 'enforce'
      ? mk(c, 'pass', '能力已启用 (enforce 模式)', 'Capability active (enforce mode)')
      : mk(c, 'warn', 'audit 模式仅记录不拦截，建议切换 enforce', 'Audit mode logs only; switch to enforce')
  }
  const on = required.filter(l => config.layers[l])
  if (on.length === required.length) {
    const tail = config.mode === 'enforce' ? '' : '（注意：audit 模式仅记录不拦截）'
    return mk(c, config.mode === 'enforce' ? 'pass' : 'warn',
      `已启用: ${required.join(', ')}${tail}`,
      `Enabled: ${required.join(', ')}${config.mode === 'enforce' ? '' : ' (audit mode: log-only)'}`)
  }
  if (on.length > 0) {
    return mk(c, 'warn',
      `部分启用: ${on.join(', ')}；缺少: ${required.filter(l => !on.includes(l)).join(', ')}`,
      `Partially enabled; missing: ${required.filter(l => !on.includes(l)).join(', ')}`)
  }
  return mk(c, 'fail', `未启用: ${required.join(', ')}`, `Not enabled: ${required.join(', ')}`)
}

function checkConfig(c: ComplianceControl, config: ShellWardConfig): ControlResult {
  return config.mode === 'enforce'
    ? mk(c, 'pass', 'enforce 模式', 'enforce mode')
    : mk(c, 'warn', 'audit 模式仅记录', 'audit mode logs only')
}

function checkAudit(c: ComplianceControl, env: EnvFacts): ControlResult {
  const a = env.auditLog
  if (!a.exists || a.entryCount === 0) {
    return mk(c, 'fail',
      '未发现审计日志或日志为空 — 无法满足留存与举证要求',
      'No audit log found or empty — retention/evidence requirement unmet')
  }
  // 判断留存跨度是否覆盖 6 个月
  if (a.oldestTs) {
    const span = Date.now() - new Date(a.oldestTs).getTime()
    if (span >= SIX_MONTHS_MS) {
      return mk(c, 'pass',
        `审计日志 ${a.entryCount} 条，最早 ${a.oldestTs.slice(0, 10)}，已覆盖 ≥6 个月`,
        `${a.entryCount} entries since ${a.oldestTs.slice(0, 10)}, ≥6 months covered`)
    }
  }
  return mk(c, 'warn',
    `审计日志已启用 (${a.entryCount} 条)，但留存尚未满 6 个月 — 需持续运行积累`,
    `Audit log active (${a.entryCount} entries) but <6 months retained — keep running`)
}

function checkEnv(c: ComplianceControl, env: EnvFacts): ControlResult {
  if (c.id === 'mlps-not-root') {
    return env.isRoot
      ? mk(c, 'fail', '正在以 root 运行 — 违反最小权限原则', 'Running as root — violates least privilege')
      : mk(c, 'pass', '非 root 运行', 'Not running as root')
  }
  if (c.id === 'cbdt-overseas-llm') {
    if (env.overseas.length > 0) {
      const names = env.overseas.map(o => o.provider_zh).join(', ')
      const namesEn = env.overseas.map(o => o.provider_en).join(', ')
      // 检出境外调用是"事实"，是否违规取决于是否发送 PII/重要数据 → 标"需评估"而非"不合规"
      return mk(c, 'warn',
        `检测到境外大模型调用: ${names}。是否违规取决于发送的数据：涉及个人信息/重要数据需走合规路径或改用境内模型；仅非个人/非重要数据通常可接受。`,
        `Overseas LLM detected: ${namesEn}. Compliance depends on the data sent — PI/important data needs a compliant path; non-personal data is usually fine.`)
    }
    return mk(c, 'pass', '未检测到境外大模型调用', 'No overseas LLM detected')
  }
  return mk(c, 'manual', '需人工确认', 'Manual check required')
}

function mk(control: ComplianceControl, status: ControlStatus, detail_zh: string, detail_en: string): ControlResult {
  return { control, status, detail_zh, detail_en }
}

// ===== 评分 =====

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 4, high: 3, medium: 2, low: 1,
}

/**
 * 加权得分：manual 项不计入分母（不惩罚路线图/人工项）。
 * pass=满分, warn=半分, fail=0。
 */
function computeScore(results: ControlResult[]): number {
  let earned = 0, possible = 0
  for (const r of results) {
    if (r.status === 'manual') continue
    const w = SEVERITY_WEIGHT[r.control.severity]
    possible += w
    if (r.status === 'pass') earned += w
    else if (r.status === 'warn') earned += w * 0.5
  }
  if (possible === 0) return 0
  return Math.round((earned / possible) * 100)
}

function gradeOf(score: number): 'A' | 'B' | 'C' | 'D' {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  return 'D'
}

export type { Regulation }
