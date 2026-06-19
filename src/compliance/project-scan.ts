// src/compliance/project-scan.ts — 项目真实风险扫描
//
// 体检的灵魂：报告的是「用户项目的真实风险」，不是「ShellWard 的开关」。
// 零依赖遍历当前项目目录，找出可截图、可定位 (文件:行) 的合规风险：
//   ① 境外大模型端点（硬编码 base_url/key）→ 数据出境风险
//   ② 硬编码密钥（API key / 私钥 / 口令 / 连接串）
//   ③ 文件中的中文 PII（身份证 / 手机号 / 银行卡）
//   ④ .env 等敏感文件权限过宽

import { readdirSync, statSync, readFileSync } from 'fs'
import { join, relative, basename } from 'path'
import { detectOverseasLLM } from '../rules/overseas-llm.js'
import { SENSITIVE_PATTERNS } from '../rules/sensitive-patterns.js'

export type FindingKind = 'overseas' | 'secret' | 'pii' | 'env-perm'

export interface ProjectFinding {
  kind: FindingKind
  /** 相对项目根的路径 */
  file: string
  line?: number
  /** 人类可读结论 */
  detail: string
  severity: 'critical' | 'high' | 'medium'
  /** 仅 overseas：命中的境外端点信息，供体检评分并入 */
  endpointId?: string
  provider_zh?: string
  provider_en?: string
}

export interface ProjectScanResult {
  root: string
  filesScanned: number
  truncated: boolean
  findings: ProjectFinding[]
  counts: Record<FindingKind, number>
}

// ===== 扫描边界（零依赖、可控） =====
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'out',
  'vendor', 'coverage', '.venv', 'venv', '__pycache__', '.cache', 'target',
])
const SCAN_EXT = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.rb', '.java', '.php', '.rs',
  '.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.sh', '.txt', '.csv',
])
const MAX_FILES = 3000
const MAX_FILE_BYTES = 512 * 1024
const MAX_FINDINGS_PER_FILE = 20
const MAX_TOTAL_FINDINGS = 500

// 密钥类 vs PII 类（按 sensitive-patterns 的 id 归类）
const SECRET_IDS = new Set([
  'openai_key', 'anthropic_key', 'aws_access', 'github_token',
  'generic_api_key', 'private_key', 'jwt', 'password', 'conn_string',
])
const PII_IDS = new Set(['id_card_cn', 'phone_cn', 'bank_card_cn', 'ssn_us', 'credit_card'])

/** 扫描项目目录，返回真实风险发现 */
export function scanProject(root: string): ProjectScanResult {
  const findings: ProjectFinding[] = []
  const state = { files: 0, truncated: false }

  walk(root, root, findings, state)

  const counts: Record<FindingKind, number> = { overseas: 0, secret: 0, pii: 0, 'env-perm': 0 }
  for (const f of findings) counts[f.kind]++

  return {
    root,
    filesScanned: state.files,
    truncated: state.truncated,
    findings,
    counts,
  }
}

function walk(
  dir: string,
  root: string,
  findings: ProjectFinding[],
  state: { files: number; truncated: boolean },
): void {
  if (state.files >= MAX_FILES || findings.length >= MAX_TOTAL_FINDINGS) {
    state.truncated = true
    return
  }
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return
  }

  for (const name of entries) {
    if (state.files >= MAX_FILES || findings.length >= MAX_TOTAL_FINDINGS) {
      state.truncated = true
      return
    }
    if (name.startsWith('.') && !name.startsWith('.env')) {
      // 跳过隐藏文件/目录，但保留 .env*
      if (name !== '.') continue
    }
    const full = join(dir, name)
    let st
    try {
      st = statSync(full)
    } catch {
      continue
    }

    if (st.isDirectory()) {
      if (SKIP_DIRS.has(name)) continue
      walk(full, root, findings, state)
      continue
    }

    if (!st.isFile()) continue

    // .env 权限检查（任意大小）
    if (/^\.env(\..+)?$/.test(name)) {
      checkEnvPerm(full, root, st.mode, findings)
    }

    // 内容扫描：仅文本类扩展 + .env*，且大小受限
    const isEnv = /^\.env(\..+)?$/.test(name)
    const ext = name.includes('.') ? name.slice(name.lastIndexOf('.')) : ''
    if (!isEnv && !SCAN_EXT.has(ext)) continue
    if (st.size > MAX_FILE_BYTES) continue

    let content: string
    try {
      content = readFileSync(full, 'utf-8')
    } catch {
      continue
    }
    state.files++
    scanContent(content, full, root, findings)
  }
}

function checkEnvPerm(full: string, root: string, mode: number, findings: ProjectFinding[]): void {
  // 仅 POSIX 有意义；Windows 上 mode 不可靠，跳过
  if (process.platform === 'win32') return
  const perm = mode & 0o777
  if (perm > 0o600) {
    findings.push({
      kind: 'env-perm',
      file: rel(root, full),
      detail: `权限过宽 (${perm.toString(8)})，建议 chmod 600 — 含密钥的 .env 不应组/其他可读`,
      severity: 'high',
    })
  }
}

function scanContent(
  content: string,
  full: string,
  root: string,
  findings: ProjectFinding[],
): void {
  const file = rel(root, full)
  const lines = content.split('\n')
  let perFile = 0
  const dedup = new Set<string>()

  for (let i = 0; i < lines.length; i++) {
    if (perFile >= MAX_FINDINGS_PER_FILE || findings.length >= MAX_TOTAL_FINDINGS) break
    const line = lines[i]
    if (!line || line.length > 4000) continue

    // ① 境外大模型端点
    const ov = detectOverseasLLM(line)
    if (ov.isOverseas) {
      const key = `overseas:${ov.endpointId}`
      if (!dedup.has(key)) {
        dedup.add(key)
        findings.push({
          kind: 'overseas',
          file,
          line: i + 1,
          detail: `境外大模型端点: ${ov.provider_zh} — 向其发送个人信息/重要数据即构成数据出境`,
          severity: 'critical',
          endpointId: ov.endpointId,
          provider_zh: ov.provider_zh,
          provider_en: ov.provider_en,
        })
        perFile++
      }
    }

    // ② / ③ 密钥与 PII
    for (const pat of SENSITIVE_PATTERNS) {
      if (perFile >= MAX_FINDINGS_PER_FILE) break
      const isSecret = SECRET_IDS.has(pat.id)
      const isPII = PII_IDS.has(pat.id)
      if (!isSecret && !isPII) continue
      const re = new RegExp(pat.regex.source, pat.regex.flags)
      let m: RegExpExecArray | null
      while ((m = re.exec(line)) !== null) {
        if (pat.validate && !pat.validate(m[0])) continue
        const key = `${pat.id}:${i}`
        if (dedup.has(key)) break
        dedup.add(key)
        findings.push({
          kind: isSecret ? 'secret' : 'pii',
          file,
          line: i + 1,
          detail: isSecret
            ? `硬编码${pat.name}: ${preview(m[0])} — 凭据不应写入源码/配置`
            : `${pat.name}: ${preview(m[0])} — 个人信息出现在文件中，需评估最小必要与脱敏`,
          severity: isSecret ? 'critical' : 'high',
        })
        perFile++
        if (perFile >= MAX_FINDINGS_PER_FILE) break
        if (!re.global) break
      }
    }
  }
}

function preview(s: string): string {
  return s.length > 10 ? s.slice(0, 6) + '***' : s.slice(0, 3) + '***'
}

function rel(root: string, full: string): string {
  const r = relative(root, full)
  return r || basename(full)
}
