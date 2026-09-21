#!/usr/bin/env npx tsx
// test-skill.ts — china-ai-compliance-audit skill 的校验器测试
//
// 成对验：示例记录必须全绿（阴性对照）；每一种该拦的错都必须真的拦住（验红）。
// 只验绿防不住「校验器其实什么都放行」。

import { readFileSync } from 'fs'
import { join } from 'path'
// @ts-expect-error — 零依赖 .mjs，无类型声明
import { validate, renderReport, loadControls } from './skills/china-ai-compliance-audit/scripts/validate-findings.mjs'
import { COMPLIANCE_CONTROLS } from './src/compliance/regulations'

const SKILL = join(process.cwd(), 'skills/china-ai-compliance-audit')
const ROOT = join(SKILL, 'examples/demo-app')

let passed = 0, failed = 0
function test(name: string, cond: boolean, detail?: string) {
  if (cond) { passed++; console.log(`  ✅ ${name}`) }
  else { failed++; console.log(`  ❌ ${name}${detail ? ' — ' + detail : ''}`) }
}

const good = () => JSON.parse(readFileSync(join(SKILL, 'examples/compliance-findings.example.json'), 'utf8'))
/** 改一处，返回错误列表 */
function errorsAfter(mutate: (doc: any) => void): string[] {
  const doc = good()
  mutate(doc)
  return validate(doc, ROOT).errors
}
const has = (errs: string[], needle: string) => errs.some((e) => e.includes(needle))
const find = (doc: any, id: string) => doc.findings.find((f: any) => f.id === id)

console.log('\n========== 合规审计 skill 校验器测试 ==========\n')

console.log('--- 控制项与 regulations.ts 零漂移 ---')
{
  const controls = loadControls()
  const src = new Map(COMPLIANCE_CONTROLS.map((c) => [c.id, c]))
  test('控制项数量一致', controls.length === COMPLIANCE_CONTROLS.length, `${controls.length} vs ${COMPLIANCE_CONTROLS.length}`)
  const drift = controls.filter((c: any) => {
    const s = src.get(c.id)
    return !s || s.regulation !== c.regulation || s.article !== c.article || s.title_zh !== c.title || s.severity !== c.severity
  })
  test('id / 法规 / 条款 / 标题 / 严重度 全部一致', drift.length === 0, drift.map((c: any) => c.id).join(', '))
  test('每项都有 look_for 取证线索', controls.every((c: any) => Array.isArray(c.look_for) && c.look_for.length > 0))
}

console.log('\n--- 阴性对照：示例记录必须全绿 ---')
{
  const r = validate(good(), ROOT)
  test('示例记录零错误', r.errors.length === 0, r.errors.join(' | '))
  test('示例覆盖全部 14 个控制项', r.stats.gap + r.stats.met + r.stats.needs_human + r.stats.not_applicable >= 14)
}

console.log('\n--- 验红：取证 ---')
{
  test('编造的文件被拦', has(errorsAfter((d) => { find(d, 'F-001').evidence[0].file = 'src/payment.ts' }), '文件不存在'))
  test('行号超出文件被拦', has(errorsAfter((d) => { find(d, 'F-007').evidence[0].line = 99 }), '没有第 99 行'))
  test('quote 不在原文被拦', has(errorsAfter((d) => { find(d, 'F-002').evidence[0].quote = 'const user = await loadCustomer(userId)' }), '找不到这段 quote'))
  test('行号写错给出真实行号', has(errorsAfter((d) => { find(d, 'F-001').evidence[1].line = 19 }), '实际在第 10 行'))
  test('行号差 2 行以内放行', errorsAfter((d) => { find(d, 'F-001').evidence[1].line = 12 }).length === 0)
  test('路径逃出项目根被拦', has(errorsAfter((d) => { find(d, 'F-001').evidence[0].file = '../../SKILL.md' }), '跑出了项目根'))
  test('绝对路径被拦', has(errorsAfter((d) => { find(d, 'F-001').evidence[0].file = '/etc/hosts' }), '绝对路径'))
  test('gap 无取证被拦', has(errorsAfter((d) => { find(d, 'F-003').evidence = [] }), '必须有至少一条'))
}

console.log('\n--- 验红：报告不许泄漏 ---')
{
  // 运行时拼出来，避免仓库里出现形似真密钥/证件号的字面量
  const fakeKey = 'sk-' + 'a1B2c3D4e5'.repeat(3)
  const fakePhone = '139' + '1234' + '5678'
  const fakeId = '11010519491231' + '002X'
  test('title 含完整密钥被拦', has(errorsAfter((d) => { find(d, 'F-001').title = `硬编码密钥 ${fakeKey}` }), '密钥'))
  test('remediation 含手机号被拦', has(errorsAfter((d) => { find(d, 'F-001').remediation = `联系 ${fakePhone} 处理并尽快整改` }), '手机号'))
  test('question 含身份证号被拦', has(errorsAfter((d) => { find(d, 'F-015').question = `客户 ${fakeId} 的数据是否做过评估？` }), '身份证号'))
  test('截断到密钥之前的引用放行', errorsAfter((d) => { find(d, 'F-001').title = '硬编码密钥 sk-*** 出现在配置里' }).length === 0)
}

console.log('\n--- 验红：裁决纪律 ---')
{
  test('gap 缺 severity 被拦', has(errorsAfter((d) => { delete find(d, 'F-002').severity }), '必须给 severity'))
  test('needs_human 带 severity 被拦', has(errorsAfter((d) => { find(d, 'F-011').severity = 'high' }), '只有 gap 才能带 severity'))
  test('gap 未经复核被拦', has(errorsAfter((d) => { delete find(d, 'F-002').verifier }), '必须经过复核'))
  test('复核已推翻却仍是 gap 被拦', has(errorsAfter((d) => { find(d, 'F-002').verifier.result = 'overturned' }), '应改为 rejected'))
  test('gap 缺 remediation 被拦', has(errorsAfter((d) => { delete find(d, 'F-002').remediation }), '必须给 remediation'))
  test('needs_human 缺具体问题被拦', has(errorsAfter((d) => { find(d, 'F-011').question = '待确认' }), '必须写 question'))
  test('rejected 缺 reason 被拦', has(errorsAfter((d) => { delete find(d, 'F-016').reason }), '必须写 reason'))
  test('未知控制项被拦', has(errorsAfter((d) => { find(d, 'F-002').control = 'gdpr-art-5' }), '不在 controls.json'))
  test('重复 id 被拦', has(errorsAfter((d) => { find(d, 'F-002').id = 'F-001' }), 'id 重复'))
  const selfRecheck = good(); find(selfRecheck, 'F-002').verifier.mode = 'self-recheck'
  const sr = validate(selfRecheck, ROOT)
  test('自查复核放行但给警告', sr.errors.length === 0 && sr.warnings.some((w: string) => w.includes('自查复核')))
}

console.log('\n--- 验红：覆盖 ---')
{
  test('悄悄跳过一个控制项被拦', has(errorsAfter((d) => { d.findings = d.findings.filter((f: any) => f.control !== 'genai-label') }), '覆盖缺口: 控制项 genai-label'))
  test('只有 rejected 记录不算覆盖，且报错说清原因', has(errorsAfter((d) => { const f = find(d, 'F-012'); f.verdict = 'rejected'; f.reason = '前端不在本仓库所以不看'; delete f.question }), 'genai-label（AI生成内容标识 (显式 + 元数据)）只剩 rejected 记录'))
}

console.log('\n--- 试跑反馈回归 ---')
{
  // Dockerfile 共 5 行且以换行结尾：末尾换行不算第 6 行
  test('末尾换行不多算一行', has(errorsAfter((d) => { find(d, 'F-007').evidence[0].line = 6 }), '只有 5 行'))
  const noBase = good(); delete noBase.baseline
  test('漏写 baseline 给警告但不报错', validate(noBase, ROOT).errors.length === 0 && validate(noBase, ROOT).warnings.some((w: string) => w.includes('没有 baseline')))
  const hot = good(); find(hot, 'F-007').severity = 'critical'
  test('严重度高于控制项参考上限给警告', validate(hot, ROOT).warnings.some((w: string) => w.includes('高于控制项 mlps-not-root')))
  test('「没找到措施」类在示例里统一为 needs_human', find(good(), 'F-010').verdict === 'needs_human')
  const allSelf = good(); allSelf.findings.forEach((f: any) => { if (f.verifier) f.verifier.mode = 'self-recheck' })
  test('全自查时报告头如实写自查', renderReport(allSelf).includes('自查复核') && !renderReport(allSelf).includes('独立复核（'))
  test('全独立时报告头写独立复核', renderReport(good()).includes('独立复核（8 条）'))
}

console.log('\n--- 报告渲染 ---')
{
  const md = renderReport(good())
  test('缺口按严重度排序（严重在前）', md.indexOf('[严重]') > -1 && md.indexOf('[严重]') < md.indexOf('[中]'))
  test('报告含免责声明', md.includes('不是法律意见'))
  test('需人工确认的问题原样进报告', md.includes('bot_readonly 在数据库里的实际授权'))
  test('已排除的候选留档', md.includes('F-016'))
}

console.log(`\n========== skill 校验器测试: ${passed} 通过, ${failed} 失败 ==========\n`)
if (failed > 0) process.exit(1)
