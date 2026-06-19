#!/usr/bin/env npx tsx
// test-compliance.ts — 合规体检引擎测试
//
// 验证：① 出境端点检测 ② 体检引擎评分逻辑 ③ 报告渲染 ④ 控制项映射完整性

import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { detectOverseasLLM } from './src/rules/overseas-llm'
import { runComplianceAudit } from './src/compliance/audit'
import type { EnvFacts } from './src/compliance/audit'
import { renderComplianceReport, renderProjectFindings } from './src/compliance/report'
import { scanProject } from './src/compliance/project-scan'
import { COMPLIANCE_CONTROLS } from './src/compliance/regulations'
import { DEFAULT_CONFIG } from './src/types'
import type { ShellWardConfig } from './src/types'

let passed = 0
let failed = 0

function test(name: string, condition: boolean, detail?: string) {
  if (condition) {
    passed++
    console.log(`  ✅ ${name}`)
  } else {
    failed++
    console.log(`  ❌ ${name}${detail ? ' — ' + detail : ''}`)
  }
}

console.log('\n========== ShellWard 合规体检测试 ==========\n')

// === 1. 境外大模型出境检测 ===
console.log('--- 境外大模型端点检测 ---')
{
  test('api.openai.com → 境外', detectOverseasLLM('https://api.openai.com/v1/chat').isOverseas)
  test('api.anthropic.com → 境外', detectOverseasLLM('base_url=https://api.anthropic.com').isOverseas)
  test('generativelanguage.googleapis.com → 境外',
    detectOverseasLLM('https://generativelanguage.googleapis.com/v1').isOverseas)
  test('openrouter.ai → 境外（聚合网关）', detectOverseasLLM('https://openrouter.ai/api/v1').isOverseas)
  const m = detectOverseasLLM('OPENAI_BASE_URL=https://api.openai.com/v1')
  test('返回 provider 名', m.provider_zh === 'OpenAI', m.provider_zh)

  // 境内/无端点不应误报
  test('境内端点 dashscope → 不误报',
    !detectOverseasLLM('https://dashscope.aliyuncs.com/api/v1').isOverseas)
  test('空字符串 → 不误报', !detectOverseasLLM('').isOverseas)
  test('普通文本 → 不误报', !detectOverseasLLM('请帮我分析这份销售数据').isOverseas)
}

// === 2. 体检引擎评分逻辑（注入 EnvFacts，结果可预期）===
console.log('\n--- 体检引擎评分 ---')

const cleanFacts: EnvFacts = {
  isRoot: false,
  auditLog: { exists: true, entryCount: 1000, oldestTs: new Date(Date.now() - 200 * 86400000).toISOString(), newestTs: new Date().toISOString() },
  overseas: [],
}

const badFacts: EnvFacts = {
  isRoot: true,
  auditLog: { exists: false, entryCount: 0 },
  overseas: [{ isOverseas: true, endpointId: 'openai', provider_zh: 'OpenAI', provider_en: 'OpenAI', host: 'api.openai.com' }],
}

{
  // 全层开启 + enforce + 干净环境 → 高分
  const good = runComplianceAudit(DEFAULT_CONFIG, cleanFacts)
  test('全开+enforce+干净 → 得分 ≥ 80', good.score >= 80, `score=${good.score}`)
  test('干净环境无 fail', good.failed === 0, `failed=${good.failed}`)
  test('grade 为 A 或 B', good.grade === 'A' || good.grade === 'B', good.grade)

  // root + 无日志 + 境外端点 → 出现 fail
  const bad = runComplianceAudit(DEFAULT_CONFIG, badFacts)
  const rootFail = bad.results.find(r => r.control.id === 'mlps-not-root')
  test('root 运行 → mlps-not-root = fail', rootFail?.status === 'fail')
  const exportFail = bad.results.find(r => r.control.id === 'cbdt-overseas-llm')
  test('境外端点 → cbdt-overseas-llm = fail', exportFail?.status === 'fail')
  const auditFail = bad.results.find(r => r.control.id === 'csl-audit-log')
  test('无审计日志 → csl-audit-log = fail', auditFail?.status === 'fail')
  test('坏环境得分 < 干净环境得分', bad.score < good.score, `${bad.score} vs ${good.score}`)

  // audit 模式应降级（能力项变 warn）
  const auditMode: ShellWardConfig = { ...DEFAULT_CONFIG, mode: 'audit' }
  const am = runComplianceAudit(auditMode, cleanFacts)
  test('audit 模式得分 ≤ enforce 模式', am.score <= good.score, `${am.score} vs ${good.score}`)

  // 关闭数据流层 → pipl-minimize 不再 pass
  const noDLP: ShellWardConfig = { ...DEFAULT_CONFIG, layers: { ...DEFAULT_CONFIG.layers, dataFlowGuard: false } }
  const nd = runComplianceAudit(noDLP, cleanFacts)
  const minimize = nd.results.find(r => r.control.id === 'pipl-minimize')
  test('关闭 dataFlowGuard → pipl-minimize = fail', minimize?.status === 'fail', minimize?.status)
}

// === 3. 报告渲染 ===
console.log('\n--- 报告渲染 ---')
{
  const report = runComplianceAudit(DEFAULT_CONFIG, badFacts)
  const md = renderComplianceReport(report, 'zh')
  test('中文报告含标题', md.includes('AI 应用合规体检报告'))
  test('中文报告含评分', md.includes('合规得分'))
  test('中文报告含优先整改项', md.includes('优先整改'))
  test('报告含五法规之一 (PIPL)', md.includes('个人信息保护法'))

  const mdEn = renderComplianceReport(report, 'en')
  test('英文报告含标题', mdEn.includes('Compliance Report'))
  test('报告含 manual 免责说明', mdEn.includes('not legal advice'))
}

// === 4. 控制项完整性 ===
console.log('\n--- 控制项映射完整性 ---')
{
  const ids = COMPLIANCE_CONTROLS.map(c => c.id)
  test('控制项 ID 无重复', new Set(ids).size === ids.length)
  test('每条控制项双语字段齐全',
    COMPLIANCE_CONTROLS.every(c => c.title_zh && c.title_en && c.remediation_zh && c.remediation_en))
  test('覆盖全部 5 部法规',
    new Set(COMPLIANCE_CONTROLS.map(c => c.regulation)).size === 5)
}

// === 5. 项目风险扫描 ===
console.log('\n--- 项目风险扫描 ---')
{
  const dir = mkdtempSync(join(tmpdir(), 'sw-scan-'))
  try {
    mkdirSync(join(dir, 'src'))
    mkdirSync(join(dir, 'node_modules'))
    writeFileSync(join(dir, '.env'), 'OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno\nOPENAI_BASE_URL=https://api.openai.com/v1\n')
    try { chmodSync(join(dir, '.env'), 0o644) } catch {}
    writeFileSync(join(dir, 'src', 'config.ts'),
      'export const URL = "https://api.anthropic.com/v1"\nconst phone = "13912345678"\nconst tok = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"\n')
    // node_modules 内的风险应被跳过
    writeFileSync(join(dir, 'node_modules', 'evil.js'), 'const k = "https://api.openai.com"\n')

    const scan = scanProject(dir)
    test('检测到境外端点', scan.counts.overseas >= 2, `overseas=${scan.counts.overseas}`)
    test('检测到硬编码密钥', scan.counts.secret >= 2, `secret=${scan.counts.secret}`)
    test('检测到 PII', scan.counts.pii >= 1, `pii=${scan.counts.pii}`)
    test('跳过 node_modules',
      !scan.findings.some(f => f.file.includes('node_modules')))
    test('发现带文件:行定位',
      scan.findings.every(f => f.kind === 'env-perm' || typeof f.line === 'number'))
    test('overseas 发现带 provider',
      scan.findings.filter(f => f.kind === 'overseas').every(f => !!f.endpointId))

    const md = renderProjectFindings(scan, 'zh')
    test('项目风险报告含定位', md.includes('src/config.ts:'))
    test('项目风险报告含分类', md.includes('数据出境风险'))

    // 干净目录无发现
    const cleanDir = mkdtempSync(join(tmpdir(), 'sw-clean-'))
    try {
      writeFileSync(join(cleanDir, 'readme.txt'), '请帮我整理这份销售数据，谢谢。\n')
      const cleanScan = scanProject(cleanDir)
      test('干净目录无 critical 发现', cleanScan.findings.filter(f => f.severity === 'critical').length === 0)
    } finally {
      rmSync(cleanDir, { recursive: true, force: true })
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// === 总结 ===
console.log(`\n========== 结果: ${passed} 通过, ${failed} 失败 ==========\n`)
if (failed > 0) process.exit(1)
