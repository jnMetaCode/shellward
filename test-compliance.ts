#!/usr/bin/env npx tsx
// test-compliance.ts — 合规体检引擎测试
//
// 验证：① 出境端点检测 ② 体检引擎评分逻辑 ③ 报告渲染 ④ 控制项映射完整性

import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { detectOverseasLLM, detectOverseasDeps } from './src/rules/overseas-llm'
import { runComplianceAudit, runProjectComplianceAudit } from './src/compliance/audit'
import type { EnvFacts } from './src/compliance/audit'
import { renderComplianceReport, renderProjectFindings } from './src/compliance/report'
import { scanProject } from './src/compliance/project-scan'
import { renderHtmlReport } from './src/compliance/html-report'
import { validateRepoUrl } from './src/web/scan-server'
import { suggestDomestic, DOMESTIC_MODELS } from './src/rules/domestic-alternatives'
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

// === 6. 境外大模型 SDK 依赖检测 ===
console.log('\n--- 境外 SDK 依赖检测 ---')
{
  const pkg = JSON.stringify({ dependencies: { openai: '^4.0.0', express: '^4' }, devDependencies: { '@anthropic-ai/sdk': '^0.20.0' } })
  const m1 = detectOverseasDeps('package.json', pkg)
  test('package.json 检出 openai + anthropic', m1.length === 2, `len=${m1.length}`)
  test('package.json 不误报 express', !m1.some(d => d.pkg === 'express'))

  const req = 'flask==2.0\nopenai>=1.0\ngoogle-generativeai\n# comment anthropic\n'
  const m2 = detectOverseasDeps('requirements.txt', req)
  test('requirements.txt 检出 openai + gemini', m2.some(d => d.pkg === 'openai') && m2.some(d => d.pkg === 'google-generativeai'))

  const gomod = 'module x\nrequire github.com/sashabaranov/go-openai v1.2.0\n'
  test('go.mod 检出 go-openai', detectOverseasDeps('go.mod', gomod).length === 1)

  test('损坏的 package.json 不崩溃', detectOverseasDeps('package.json', '{bad json').length === 0)
  test('纯净依赖无误报', detectOverseasDeps('package.json', '{"dependencies":{"lodash":"^4"}}').length === 0)
}

// === 7. 发现驱动评分 + 依赖并入 + 报告导出 ===
console.log('\n--- 发现驱动评分 + 项目体检 ---')
{
  const dir = mkdtempSync(join(tmpdir(), 'sw-proj-'))
  try {
    writeFileSync(join(dir, 'package.json'),
      JSON.stringify({ dependencies: { openai: '^4', '@anthropic-ai/sdk': '^0.2' } }, null, 2))
    writeFileSync(join(dir, 'app.py'), 'KEY = "sk-abc123def456ghi789jkl012mno"\nphone = "13912345678"\n')

    const { report, scan } = runProjectComplianceAudit(DEFAULT_CONFIG, dir)
    test('体检检出境外 SDK 依赖', scan.findings.some(f => f.kind === 'overseas' && f.detail.includes('SDK')))
    test('发现驱动扣分生效', (report.projectPenalty || 0) > 0, `penalty=${report.projectPenalty}`)
    test('有风险时得分低于满分', report.score < 100, `score=${report.score}`)

    // 对比：纯控制项评分（无项目风险）应更高
    const cleanFactsLocal: EnvFacts = { isRoot: false, auditLog: { exists: true, entryCount: 10 }, overseas: [] }
    const baseline = runComplianceAudit(DEFAULT_CONFIG, cleanFactsLocal)
    test('项目体检得分 ≤ 无风险基线', report.score <= baseline.score, `${report.score} vs ${baseline.score}`)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// === 8. 境内合规替代建议 ===
console.log('\n--- 境内合规替代建议 ---')
{
  test('境内模型库非空且含通义/DeepSeek', DOMESTIC_MODELS.some(m => m.id === 'qwen') && DOMESTIC_MODELS.some(m => m.id === 'deepseek'))
  test('所有列出的境内模型有 base_url', DOMESTIC_MODELS.every(m => m.baseUrl.startsWith('https://')))

  const sOpenAI = suggestDomestic('openai', 'OpenAI', 'OpenAI')
  test('OpenAI → 迁移难度低(零代码)', sOpenAI.difficulty_zh.includes('低') && sOpenAI.difficulty_zh.includes('base_url'))
  test('OpenAI → 给出境内替代', sOpenAI.alternatives.length >= 3)

  const sAnthropic = suggestDomestic('anthropic', 'Anthropic Claude', 'Anthropic Claude')
  test('Anthropic → 迁移难度中(需改代码)', sAnthropic.difficulty_zh.includes('中'))

  // 报告渲染：含境外依赖时出现替代建议段
  const dir = mkdtempSync(join(tmpdir(), 'sw-dom-'))
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { openai: '^4' } }))
    const scan = scanProject(dir)
    const md = renderProjectFindings(scan, 'zh')
    test('报告含"境内合规替代建议"段', md.includes('境内合规替代建议'))
    test('报告含具体境内 base_url', md.includes('dashscope.aliyuncs.com'))
    test('报告含零代码迁移提示', md.includes('base_url') && md.includes('无需改动'))

    // 无境外风险的干净项目不应出现替代段
    const cleanDir = mkdtempSync(join(tmpdir(), 'sw-domc-'))
    try {
      writeFileSync(join(cleanDir, 'a.txt'), 'hello')
      const cleanMd = renderProjectFindings(scanProject(cleanDir), 'zh')
      test('干净项目无替代建议段', !cleanMd.includes('境内合规替代建议'))
    } finally { rmSync(cleanDir, { recursive: true, force: true }) }
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

// === 9. HTML 合规报告 ===
console.log('\n--- HTML 合规报告 ---')
{
  const dir = mkdtempSync(join(tmpdir(), 'sw-html-'))
  try {
    // 含境外依赖 + 一个会引入 HTML 特殊字符的文件名风险点
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { openai: '^4' } }))
    writeFileSync(join(dir, 'a.ts'), 'const t = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"\n')
    const { report, scan } = runProjectComplianceAudit(DEFAULT_CONFIG, dir)
    const html = renderHtmlReport(report, scan, 'zh', { root: dir })

    test('HTML 是完整文档', html.startsWith('<!DOCTYPE html>') && html.includes('</html>'))
    test('HTML 自包含(内联 CSS, 无外链)', html.includes('<style>') && !/<link|<script src=/.test(html))
    test('HTML 含评分', html.includes(String(report.score)))
    test('HTML 含项目实测风险', html.includes('项目实测风险'))
    test('HTML 含境内替代建议', html.includes('境内合规替代建议') && html.includes('dashscope'))
    test('HTML 含五法规之一', html.includes('个人信息保护法'))
    test('HTML 含打印样式', html.includes('@media print'))

    // 英文版
    const htmlEn = renderHtmlReport(report, scan, 'en', { root: dir })
    test('英文 HTML 标题正确', htmlEn.includes('AI Application Compliance Report'))

    // HTML 转义：注入恶意字符串不应破坏结构
    const evil = { ...scan, findings: [{ kind: 'secret' as const, file: '<img src=x onerror=alert(1)>', detail: 'a & b <script>', severity: 'critical' as const }] }
    const safe = renderHtmlReport(report, evil, 'zh', { root: '<b>x</b>' })
    test('HTML 转义恶意输入', !safe.includes('<img src=x') && !safe.includes('<script>a') && safe.includes('&lt;img'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// === 10. 降误报：占位符 / 噪声文件 / .shellwardignore ===
console.log('\n--- 降误报与忽略 ---')
{
  const dir = mkdtempSync(join(tmpdir(), 'sw-fp-'))
  try {
    // 占位符密钥不应被报；结构真实的密钥应被报
    writeFileSync(join(dir, 'placeholder.ts'),
      'const k1 = "your-api-key-here"\nconst k2 = "sk-EXAMPLExxxxxxxxxxxxxxxxxxxx"\nconst pw = "password: changeme"\n')
    writeFileSync(join(dir, 'real.ts'), 'const k = "sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq"\n')
    // 噪声文件（lock）含 key 状字符串，应被默认跳过
    writeFileSync(join(dir, 'package-lock.json'), '{"x":"sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq"}')
    // 被 .shellwardignore 排除的目录
    mkdirSync(join(dir, 'samples'))
    writeFileSync(join(dir, 'samples', 'leak.ts'), 'const k = "sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq"\n')
    writeFileSync(join(dir, '.shellwardignore'), '# test\nsamples/\n')

    // .env 模板文件不应报权限；真实 .env 应报
    writeFileSync(join(dir, '.env.example'), 'OPENAI_API_KEY=your-key-here\n')
    try { chmodSync(join(dir, '.env.example'), 0o644) } catch {}
    writeFileSync(join(dir, '.env'), 'OPENAI_API_KEY=sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq\n')
    try { chmodSync(join(dir, '.env'), 0o644) } catch {}

    const scan = scanProject(dir)
    const envPerm = scan.findings.filter(f => f.kind === 'env-perm').map(f => f.file)
    test('.env.example 模板不报权限', !envPerm.some(f => f.includes('.env.example')), envPerm.join(','))
    const secretFiles = scan.findings.filter(f => f.kind === 'secret').map(f => f.file)
    test('占位符密钥被过滤', !secretFiles.some(f => f.includes('placeholder')), secretFiles.join(','))
    test('结构真实密钥被检出', secretFiles.some(f => f.includes('real.ts')))
    test('lock 文件被跳过', !secretFiles.some(f => f.includes('package-lock')))
    test('.shellwardignore 目录被排除', !secretFiles.some(f => f.includes('samples')))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }

  // ShellWard 自身仓库不应"对自己狼来了"
  const self = scanProject(process.cwd())
  test('ShellWard 自身仓库自扫无 critical 误报',
    self.findings.filter(f => f.severity === 'critical').length === 0,
    `criticals=${self.findings.filter(f => f.severity === 'critical').length}`)
}

// === 11. 部署上下文：静态扫描不虚报能力项已启用 ===
console.log('\n--- 部署/静态扫描上下文 ---')
{
  // deployed=true（MCP/插件，ShellWard 在运行）：能力项如实评估为 pass
  const dep = runComplianceAudit(DEFAULT_CONFIG, cleanFacts, { deployed: true })
  const spiDep = dep.results.find(r => r.control.id === 'pipl-spi-detect')
  test('已部署：能力项判 pass', spiDep?.status === 'pass', spiDep?.status)

  // deployed=false（静态扫描）：能力/审计项不虚报，改为 ⚪ manual
  const stat = runComplianceAudit(DEFAULT_CONFIG, cleanFacts, { deployed: false })
  const spiStat = stat.results.find(r => r.control.id === 'pipl-spi-detect')
  test('静态扫描：能力项不虚报 pass（变 manual）', spiStat?.status === 'manual', spiStat?.status)
  const auditStat = stat.results.find(r => r.control.id === 'csl-audit-log')
  test('静态扫描：审计项变 manual（不虚报留存达标）', auditStat?.status === 'manual', auditStat?.status)
  // env 类（境外/root）静态可观测，仍如实评估
  const rootStat = stat.results.find(r => r.control.id === 'mlps-not-root')
  test('静态扫描：env 类(root)仍如实评估', rootStat?.status === 'pass' || rootStat?.status === 'fail')
  test('静态扫描无 pass 虚高（能力项不计 pass）',
    stat.results.filter(r => r.control.method === 'capability').every(r => r.status === 'manual'))

  // CLI 入口默认就是静态扫描上下文
  const dir = mkdtempSync(join(tmpdir(), 'sw-ctx-'))
  try {
    writeFileSync(join(dir, 'a.txt'), 'hello')
    const { report } = runProjectComplianceAudit(DEFAULT_CONFIG, dir)
    // 能力项默认 manual（不虚报）——但 pipl-spi-detect 静态可查，直接连扫描结果（不算虚报）
    test('CLI 体检：能力项均为 manual（pipl-spi-detect 除外，它静态可查）',
      report.results.filter(r => r.control.method === 'capability' && r.control.id !== 'pipl-spi-detect').every(r => r.status === 'manual'))
    const spi = report.results.find(r => r.control.id === 'pipl-spi-detect')
    test('CLI 体检：敏感个人信息识别已直接判定(非待核验)', spi?.status === 'pass' || spi?.status === 'fail', spi?.status)
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

// === 12. web 扫描器 URL 校验（安全） ===
console.log('\n--- web 扫描器 URL 校验 ---')
{
  const ok = (u: string) => validateRepoUrl(u).ok
  test('github 公开仓库 → 通过', ok('https://github.com/openai/openai-quickstart-node'))
  test('gitee .git 后缀 → 通过', ok('https://gitee.com/owner/repo.git'))
  test('gitlab → 通过', ok('https://gitlab.com/owner/repo'))
  test('非白名单域名 → 拒绝', !ok('https://evil.com/a/b'))
  test('http(非https) → 拒绝', !ok('http://github.com/a/b'))
  test('带凭据(@) → 拒绝', !ok('https://user:pw@github.com/a/b'))
  test('空 → 拒绝', !ok(''))
  test('含空格 → 拒绝', !ok('https://github.com/a /b'))
  test('缺仓库名 → 拒绝', !ok('https://github.com/owner'))
  test('命令注入字符 → 拒绝', !ok('https://github.com/a/b;rm -rf'))
}

// === 13. Markdown 文档扫描策略 + 诚实静态评分 ===
console.log('\n--- Markdown 策略 + 诚实评分 ---')
{
  const dir = mkdtempSync(join(tmpdir(), 'sw-md-'))
  try {
    // README 文档里的示例密钥/PII 不应误报；但 .md 里真实境外端点应报
    writeFileSync(join(dir, 'README.md'),
      '示例: password: MyP@ssw0rd123  手机 13912345678  SSN 123-45-6789\n调用 https://api.openai.com/v1\n')
    // 真实代码文件里的密钥仍要报
    writeFileSync(join(dir, 'app.ts'), 'const k="sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq"\n')
    const scan = scanProject(dir)
    const mdSecret = scan.findings.some(f => f.file === 'README.md' && (f.kind === 'secret' || f.kind === 'pii'))
    test('Markdown 文档示例密钥/PII 不误报', !mdSecret)
    test('Markdown 里真实境外端点仍检出', scan.findings.some(f => f.file === 'README.md' && f.kind === 'overseas'))
    test('代码文件密钥仍检出', scan.findings.some(f => f.file === 'app.ts' && f.kind === 'secret'))
    test('被扫描文件数包含 .md', scan.filesScanned >= 2)

    // 诚实静态评分：不报"优秀"，标记 staticScan
    const { report } = runProjectComplianceAudit(DEFAULT_CONFIG, dir)
    test('体检标记 staticScan', report.staticScan === true)
    test('体检记录 filesScanned', (report.filesScanned ?? 0) >= 2)
    const html = renderHtmlReport(report, scan, 'zh', { root: dir })
    test('HTML 不含"优秀"误导词', !html.includes('优秀'))
    test('HTML 含静态扫描诚实声明', html.includes('本次为静态扫描') && html.includes('未验证'))
  } finally { rmSync(dir, { recursive: true, force: true }) }

  // 干净项目静态扫描：HTML 应显示"未发现可观测风险"而非"优秀"
  const clean = mkdtempSync(join(tmpdir(), 'sw-cl2-'))
  try {
    writeFileSync(join(clean, 'index.js'), 'console.log("hi")\n')
    const { report, scan } = runProjectComplianceAudit(DEFAULT_CONFIG, clean)
    const html = renderHtmlReport(report, scan, 'zh', { root: clean })
    test('干净静态扫描 HTML 显示"未发现可观测风险"', html.includes('未发现可观测风险'))
  } finally { rmSync(clean, { recursive: true, force: true }) }
}

// === 总结 ===
console.log(`\n========== 结果: ${passed} 通过, ${failed} 失败 ==========\n`)
if (failed > 0) process.exit(1)
