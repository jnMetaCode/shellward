#!/usr/bin/env node
// validate-findings.mjs — 合规审计发现的确定性校验器（零依赖）
//
// agent 写出的每一条发现都要过这道闸，过不了就不算数：
//   ① 结构：字段、枚举、控制项 id 是否合法
//   ② 取证：引用的 文件:行 真的存在，且 quote 真的出现在那几行里（防幻觉）
//   ③ 防泄漏：报告里不许出现完整密钥 / 手机号 / 身份证号（合规报告自己不能违规）
//   ④ 裁决纪律：gap / met 必须经复核且复核结论为 upheld；needs_human 不许带严重度
//   ⑤ 覆盖：controls.json 里每个控制项都必须有结论，不许悄悄跳过
//
// 用法:
//   node validate-findings.mjs <compliance-findings.json> [--root <项目根>] [--report <输出.md>]
// 退出码: 0 通过 · 1 有错误 · 2 用法错误

import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs'
import { resolve, dirname, join, relative, isAbsolute, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const VERDICTS = ['gap', 'met', 'needs_human', 'not_applicable', 'rejected']
const SEVERITIES = ['critical', 'high', 'medium', 'low']
const SOURCES = ['baseline', 'agent']
const VERIFIER_MODES = ['independent', 'self-recheck']
/** quote 在声明行上下各放宽几行（agent 数行号常差一两行，但差太多就是没看原文） */
const LINE_SLACK = 2
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 }
const MIN_QUOTE = 6

// 不许原样出现在报告里的内容。quote 只需要是原文的一段，截到密钥之前即可。
const LEAK_PATTERNS = [
  ['OpenAI/Anthropic 风格密钥', /sk-[A-Za-z0-9_-]{20,}/],
  ['GitHub Token', /gh[pousr]_[A-Za-z0-9]{30,}/],
  ['AWS Access Key', /AKIA[0-9A-Z]{16}/],
  ['私钥块', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['身份证号', /(?<!\d)\d{17}[\dXx](?!\d)/],
  ['银行卡号', /(?<!\d)\d{16,19}(?!\d)/],
  ['手机号', /(?<!\d)1[3-9]\d{9}(?!\d)/],
]

function parseArgs(argv) {
  const out = { file: null, root: null, report: null }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--root') out.root = argv[++i]
    else if (a === '--report') out.report = argv[++i]
    else if (a === '--help' || a === '-h') out.help = true
    else if (!out.file) out.file = a
  }
  return out
}

const norm = (s) => String(s).replace(/\s+/g, ' ').trim()

export function loadControls() {
  const raw = JSON.parse(readFileSync(join(HERE, '..', 'controls.json'), 'utf8'))
  return raw.controls
}

function leakIn(text) {
  for (const [name, re] of LEAK_PATTERNS) if (re.test(text)) return name
  return null
}

/** 校验单条取证。返回错误字符串数组。 */
function checkEvidence(ev, root, where, fileCache) {
  const errs = []
  if (!ev || typeof ev !== 'object') return [`${where}: evidence 项必须是对象`]
  const { file, line, quote } = ev
  if (typeof file !== 'string' || !file) return [`${where}: evidence.file 缺失`]
  if (isAbsolute(file)) return [`${where}: evidence.file 必须是相对项目根的路径，收到绝对路径 ${file}`]
  const abs = resolve(root, file)
  const rel = relative(root, abs)
  if (rel === '..' || rel.startsWith('..' + sep)) return [`${where}: evidence.file 跑出了项目根: ${file}`]
  if (!existsSync(abs) || !statSync(abs).isFile()) return [`${where}: 文件不存在: ${file}（是不是编的？）`]
  if (!Number.isInteger(line) || line < 1) return [`${where}: evidence.line 必须是 ≥1 的整数`]
  if (typeof quote !== 'string' || norm(quote).length < MIN_QUOTE)
    return [`${where}: evidence.quote 至少 ${MIN_QUOTE} 个字符，要能在原文里定位`]

  const leak = leakIn(quote)
  if (leak) errs.push(`${where}: quote 里含有完整的${leak}——报告不能泄漏它，只引用到密钥/号码之前的部分`)

  let lines = fileCache.get(abs)
  if (!lines) {
    lines = readFileSync(abs, 'utf8').split(/\r?\n/)
    if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop() // 末尾换行不算一行
    fileCache.set(abs, lines)
  }
  if (line > lines.length) {
    errs.push(`${where}: ${file} 只有 ${lines.length} 行，没有第 ${line} 行`)
    return errs
  }
  const q = norm(quote)
  const lo = Math.max(1, line - LINE_SLACK)
  const hi = Math.min(lines.length, line + LINE_SLACK)
  const windowText = norm(lines.slice(lo - 1, hi).join(' '))
  if (!windowText.includes(q)) {
    const elsewhere = lines.findIndex((l) => norm(l).includes(q))
    errs.push(
      elsewhere >= 0
        ? `${where}: quote 不在 ${file}:${line} 附近，实际在第 ${elsewhere + 1} 行——行号写错了`
        : `${where}: 在 ${file} 里找不到这段 quote——请回到原文重新取证，不要凭记忆写`,
    )
  }
  return errs
}

/** 校验整份发现。返回 { errors, warnings, stats }。 */
export function validate(doc, root, controls = loadControls()) {
  const errors = []
  const warnings = []
  const controlIds = new Set(controls.map((c) => c.id))
  const fileCache = new Map()

  if (!doc || typeof doc !== 'object') return { errors: ['顶层必须是 JSON 对象'], warnings, stats: {} }
  if (doc.schema !== 1) errors.push('schema 必须为 1')
  if (typeof doc.project !== 'string' || !doc.project) errors.push('project（项目名）缺失')
  if (!Array.isArray(doc.findings)) return { errors: [...errors, 'findings 必须是数组'], warnings, stats: {} }
  if (!doc.baseline) warnings.push('没有 baseline：如果阶段 0 的 shellward scan 跑成了，请补上 { tool, score, grade }；没跑成请在汇报里说明')

  const seen = new Set()
  const covered = new Set()
  const stats = Object.fromEntries(VERDICTS.map((v) => [v, 0]))

  doc.findings.forEach((f, i) => {
    const where = f && typeof f.id === 'string' ? f.id : `findings[${i}]`
    if (!f || typeof f !== 'object') return errors.push(`${where}: 必须是对象`)
    if (typeof f.id !== 'string' || !/^F-\d{3,}$/.test(f.id)) errors.push(`${where}: id 形如 F-001`)
    else if (seen.has(f.id)) errors.push(`${where}: id 重复`)
    else seen.add(f.id)

    if (!controlIds.has(f.control)) errors.push(`${where}: control "${f.control}" 不在 controls.json 里`)
    if (!VERDICTS.includes(f.verdict)) return errors.push(`${where}: verdict 必须是 ${VERDICTS.join(' / ')}`)
    stats[f.verdict]++
    if (f.verdict !== 'rejected' && controlIds.has(f.control)) covered.add(f.control)

    if (typeof f.title !== 'string' || norm(f.title).length < 4) errors.push(`${where}: title 缺失或过短`)
    if (!SOURCES.includes(f.source)) errors.push(`${where}: source 必须是 ${SOURCES.join(' / ')}`)

    for (const field of ['title', 'remediation', 'question', 'reason']) {
      const leak = typeof f[field] === 'string' && leakIn(f[field])
      if (leak) errors.push(`${where}: ${field} 里含有完整的${leak}`)
    }

    const evidence = Array.isArray(f.evidence) ? f.evidence : []
    evidence.forEach((ev, j) => errors.push(...checkEvidence(ev, root, `${where}.evidence[${j}]`, fileCache)))

    const needsSeverity = f.verdict === 'gap'
    if (needsSeverity && !SEVERITIES.includes(f.severity)) errors.push(`${where}: gap 必须给 severity (${SEVERITIES.join('/')})`)
    const ctl = controls.find((c) => c.id === f.control)
    if (needsSeverity && ctl && SEVERITIES.includes(f.severity) && SEV_RANK[f.severity] < SEV_RANK[ctl.severity])
      warnings.push(`${where}: severity ${f.severity} 高于控制项 ${ctl.id} 的参考上限 ${ctl.severity}，请在 verifier.note 里说明理由`)
    if (!needsSeverity && f.severity !== undefined)
      errors.push(`${where}: 只有 gap 才能带 severity；${f.verdict} 带严重度等于替人下了结论`)

    if (f.verdict === 'gap' || f.verdict === 'met') {
      if (evidence.length === 0) errors.push(`${where}: ${f.verdict} 必须有至少一条 文件:行 取证`)
      const v = f.verifier
      if (!v || typeof v !== 'object') errors.push(`${where}: ${f.verdict} 必须经过复核（verifier）`)
      else {
        if (!VERIFIER_MODES.includes(v.mode)) errors.push(`${where}: verifier.mode 必须是 ${VERIFIER_MODES.join(' / ')}`)
        if (v.result === 'overturned') errors.push(`${where}: 复核已推翻，verdict 应改为 rejected 并写 reason`)
        else if (v.result !== 'upheld') errors.push(`${where}: verifier.result 必须是 upheld`)
        if (v.mode === 'self-recheck') warnings.push(`${where}: 自查复核（没有独立 agent），可信度低于独立复核`)
      }
    }
    if (f.verdict === 'gap' && (typeof f.remediation !== 'string' || norm(f.remediation).length < 6))
      errors.push(`${where}: gap 必须给 remediation（具体怎么改）`)
    if (f.verdict === 'needs_human' && (typeof f.question !== 'string' || norm(f.question).length < 8))
      errors.push(`${where}: needs_human 必须写 question——一个人能直接回答的具体事实问题`)
    if ((f.verdict === 'rejected' || f.verdict === 'not_applicable') && (typeof f.reason !== 'string' || norm(f.reason).length < 6))
      errors.push(`${where}: ${f.verdict} 必须写 reason`)
  })

  const touched = new Set(doc.findings.map((f) => f && f.control))
  for (const c of controls) {
    if (covered.has(c.id)) continue
    errors.push(
      touched.has(c.id)
        ? `覆盖缺口: 控制项 ${c.id}（${c.title}）只剩 rejected 记录——rejected 不算结论，请补一条 gap / met / needs_human / not_applicable`
        : `覆盖缺口: 控制项 ${c.id}（${c.title}）没有任何记录——不许悄悄跳过`,
    )
  }

  return { errors, warnings, stats }
}

const SEV_ZH = { critical: '严重', high: '高', medium: '中', low: '低' }

function reviewLine(doc) {
  const reviewed = doc.findings.filter((f) => f.verifier)
  const indep = reviewed.filter((f) => f.verifier.mode === 'independent').length
  if (reviewed.length === 0) return '无需复核的记录'
  if (indep === reviewed.length) return `独立复核（${indep} 条）`
  if (indep === 0) return `自查复核（${reviewed.length} 条，无独立 agent，可信度较低）`
  return `复核（独立 ${indep} 条 / 自查 ${reviewed.length - indep} 条）`
}

/** 从已校验的记录确定性地渲染报告——报告不经 LLM 转写，所以不会和记录对不上。 */
export function renderReport(doc, controls = loadControls()) {
  const byId = new Map(controls.map((c) => [c.id, c]))
  const of = (v) => doc.findings.filter((f) => f.verdict === v)
  const ref = (f) => {
    const c = byId.get(f.control)
    return c ? `${c.regulation} · ${c.article} · ${c.title}` : f.control
  }
  const evLines = (f) => (f.evidence || []).map((e) => `  - \`${e.file}:${e.line}\` — \`${norm(e.quote)}\``).join('\n')
  const gaps = of('gap').sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])
  const out = []

  out.push(`# 合规审计报告 · ${doc.project}`, '')
  if (doc.audited_at) out.push(`审计时间：${doc.audited_at}`)
  if (doc.baseline && doc.baseline.score !== undefined)
    out.push(`确定性基线：shellward scan ${doc.baseline.score}/100 [${doc.baseline.grade ?? '-'}]`)
  out.push(
    '',
    `| 缺口 | 已找到的措施 | 需人工确认 | 不适用 | 已排除 |`,
    `|---|---|---|---|---|`,
    `| ${gaps.length} | ${of('met').length} | ${of('needs_human').length} | ${of('not_applicable').length} | ${of('rejected').length} |`,
    '',
    `> 本报告由 agent 取证、${reviewLine(doc)}、脚本校验生成：每条 \`文件:行\` 引用都经脚本核对确实存在。`,
    '> 它是技术自查材料，**不是法律意见**；备案、定级、PIA 等主体责任不能由工具代替。',
    '',
  )

  out.push('## 缺口（按严重度）', '')
  if (gaps.length === 0) out.push('无。', '')
  for (const f of gaps) {
    out.push(`### ${f.id} · [${SEV_ZH[f.severity]}] ${f.title}`, '', `- 依据：${ref(f)}`, `- 取证：`, evLines(f), `- 整改：${f.remediation}`)
    if (f.verifier) out.push(`- 复核：${f.verifier.mode === 'independent' ? '独立 agent' : '自查'} · 维持${f.verifier.note ? ` · ${f.verifier.note}` : ''}`)
    out.push('')
  }

  out.push('## 需要人来回答的问题', '', '这些事实不在代码仓库里，工具不替你下结论。', '')
  if (of('needs_human').length === 0) out.push('无。', '')
  for (const f of of('needs_human')) out.push(`- **${f.id}** ${f.question}  \n  依据：${ref(f)}`)
  out.push('')

  out.push('## 已找到的措施', '', '每条只说明标题里的那个命题成立，**不代表对应控制项整体满足**。', '')
  if (of('met').length === 0) out.push('无。', '')
  for (const f of of('met')) out.push(`- **${f.id}** ${f.title} — ${ref(f)}`, evLines(f))
  out.push('')

  out.push('## 不适用', '')
  if (of('not_applicable').length === 0) out.push('无。', '')
  for (const f of of('not_applicable')) out.push(`- **${f.id}** ${ref(f)} — ${f.reason}`)
  out.push('')

  out.push('## 已排除的候选（留档，方便复审）', '')
  if (of('rejected').length === 0) out.push('无。', '')
  for (const f of of('rejected')) out.push(`- **${f.id}** ${f.title} — ${f.reason}`)
  out.push('')
  return out.join('\n')
}

function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.help || !args.file) {
    console.error('用法: node validate-findings.mjs <compliance-findings.json> [--root <项目根>] [--report <输出.md>]')
    process.exit(args.help ? 0 : 2)
  }
  let doc
  try {
    doc = JSON.parse(readFileSync(args.file, 'utf8'))
  } catch (e) {
    console.error(`✗ 读不了 ${args.file}: ${e.message}`)
    process.exit(1)
  }
  const root = resolve(args.root ?? dirname(resolve(args.file)))
  const { errors, warnings, stats } = validate(doc, root)
  for (const w of warnings) console.error(`⚠ ${w}`)
  if (errors.length) {
    for (const e of errors) console.error(`✗ ${e}`)
    console.error(`\n${errors.length} 处未通过。修完重跑——没过校验的发现不许写进报告。`)
    process.exit(1)
  }
  console.log(`✓ ${doc.findings.length} 条记录通过校验 · ` + VERDICTS.map((v) => `${v} ${stats[v]}`).join(' · '))
  if (args.report) {
    writeFileSync(args.report, renderReport(doc))
    console.log(`✓ 报告已生成: ${args.report}`)
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
