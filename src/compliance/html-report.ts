// src/compliance/html-report.ts — HTML 合规报告（合规包雏形）
//
// 终端输出给开发者看；这份 HTML 给法务/合规/测评机构看 —— 可在浏览器打开、
// 打印成 PDF、用于等保/PIPL 备案存档。自包含（内联 CSS、零外部依赖、无需联网）。

import { REGULATION_NAMES } from './regulations.js'
import type { Regulation } from './regulations.js'
import type { ComplianceReport, ControlResult, ControlStatus } from './audit.js'
import type { ProjectScanResult, FindingKind } from './project-scan.js'
import { suggestDomestic } from '../rules/domestic-alternatives.js'

const STATUS: Record<ControlStatus, { zh: string; en: string; cls: string }> = {
  pass: { zh: '合规', en: 'Pass', cls: 'pass' },
  warn: { zh: '部分', en: 'Partial', cls: 'warn' },
  fail: { zh: '不合规', en: 'Fail', cls: 'fail' },
  manual: { zh: '待确认', en: 'Manual', cls: 'manual' },
}

const KIND: Record<FindingKind, { zh: string; en: string }> = {
  overseas: { zh: '数据出境风险', en: 'Data export risk' },
  secret: { zh: '硬编码密钥', en: 'Hardcoded secret' },
  pii: { zh: '个人信息暴露', en: 'PII exposure' },
  'env-perm': { zh: '.env 权限', en: '.env permission' },
}
const KIND_ORDER: FindingKind[] = ['overseas', 'secret', 'pii', 'env-perm']
const REG_ORDER: Regulation[] = ['CSL', 'PIPL', 'MLPS', 'CBDT', 'GENAI']

const GRADE_COLOR: Record<string, string> = { A: '#15803d', B: '#65a30d', C: '#d97706', D: '#dc2626' }

export interface HtmlReportMeta {
  /** 扫描的项目根 */
  root: string
}

/** 生成自包含 HTML 合规报告 */
export function renderHtmlReport(
  report: ComplianceReport,
  scan: ProjectScanResult,
  locale: 'zh' | 'en',
  meta: HtmlReportMeta,
): string {
  const zh = locale === 'zh'
  const t = (z: string, e: string) => (zh ? z : e)
  const gradeColor = GRADE_COLOR[report.grade] || '#475569'
  const when = report.generatedAt.slice(0, 19).replace('T', ' ')

  const sections: string[] = []

  // ===== 评分卡 =====
  sections.push(`
  <section class="score-card">
    <div class="gauge" style="--c:${gradeColor}">
      <div class="score">${report.score}<span>/100</span></div>
      <div class="grade" style="color:${gradeColor}">${esc(report.grade)}</div>
    </div>
    <div class="summary">
      <div class="bar"><div class="fill" style="width:${report.score}%;background:${gradeColor}"></div></div>
      <ul class="counts">
        <li class="pass">🟢 ${t('合规', 'Pass')} ${report.passed}</li>
        <li class="warn">🟡 ${t('部分', 'Partial')} ${report.warned}</li>
        <li class="fail">🔴 ${t('不合规', 'Fail')} ${report.failed}</li>
        <li class="manual">⚪ ${t('待确认', 'Manual')} ${report.manual}</li>
      </ul>
      ${report.projectPenalty ? `<p class="penalty">${t('含项目实测风险扣分', 'Includes project-scan penalty')} −${report.projectPenalty}</p>` : ''}
    </div>
  </section>`)

  // ===== 项目实测风险 =====
  sections.push(`<h2>🔍 ${t('项目实测风险', 'Project Scan Findings')}</h2>`)
  sections.push(`<p class="muted">${t('已扫描', 'Scanned')} ${scan.filesScanned} ${t('个文件', 'files')}${scan.truncated ? t('（已达上限）', ' (limit reached)') : ''}</p>`)
  if (scan.findings.length === 0) {
    sections.push(`<p class="ok">🟢 ${t('未在项目文件中发现硬编码密钥、个人信息暴露或境外端点。', 'No hardcoded secrets, PII, or overseas endpoints found.')}</p>`)
  } else {
    for (const kind of KIND_ORDER) {
      const items = scan.findings.filter(f => f.kind === kind)
      if (items.length === 0) continue
      sections.push(`<h3>${t(KIND[kind].zh, KIND[kind].en)} (${items.length})</h3>`)
      sections.push('<table class="findings"><thead><tr>'
        + `<th>${t('位置', 'Location')}</th><th>${t('说明', 'Detail')}</th><th>${t('严重度', 'Severity')}</th></tr></thead><tbody>`)
      for (const f of items) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file
        sections.push(`<tr><td class="loc">${esc(loc)}</td><td>${esc(f.detail)}</td><td class="sev-${f.severity}">${f.severity}</td></tr>`)
      }
      sections.push('</tbody></table>')
    }
  }

  // ===== 境内合规替代建议 =====
  const overseas = scan.findings.filter(f => f.kind === 'overseas')
  if (overseas.length > 0) {
    const seen = new Set<string>()
    const providers: { key: string; zh?: string; en?: string }[] = []
    for (const f of overseas) {
      const k = (f.endpointId || f.provider_en || f.provider_zh || '').toLowerCase()
      if (!k || seen.has(k)) continue
      seen.add(k)
      providers.push({ key: f.endpointId || f.provider_en || '', zh: f.provider_zh, en: f.provider_en })
    }
    sections.push(`<h2>✅ ${t('境内合规替代建议', 'Domestic Compliance Alternatives')}</h2>`)
    sections.push('<ul class="migrate">')
    for (const p of providers) {
      const s = suggestDomestic(p.key, p.zh, p.en)
      sections.push(`<li><b>${esc(zh ? s.overseas_zh : s.overseas_en)}</b> → ${esc(zh ? s.difficulty_zh : s.difficulty_en)}</li>`)
    }
    sections.push('</ul>')
    const alts = suggestDomestic(providers[0].key, providers[0].zh, providers[0].en).alternatives
    sections.push('<table class="findings"><thead><tr>'
      + `<th>${t('境内模型', 'Domestic model')}</th><th>${t('厂商', 'Vendor')}</th><th>${t('OpenAI 兼容 base_url', 'OpenAI-compatible base_url')}</th></tr></thead><tbody>`)
    for (const m of alts) {
      sections.push(`<tr><td>${esc(zh ? m.name_zh : m.name_en)}</td><td>${esc(m.vendor_zh)}</td><td class="loc">${esc(m.baseUrl)}</td></tr>`)
    }
    sections.push('</tbody></table>')
    sections.push(`<p class="muted">${t('对使用 openai SDK 的项目：通常仅需把 base_url 与 api_key 换成上表任一境内模型即可，业务代码无需改动。', 'For openai-SDK projects: usually just swap base_url + api_key — no code change.')}</p>`)
  }

  // ===== 控制项明细 =====
  sections.push(`<h2>📋 ${t('合规控制项明细', 'Compliance Controls')}</h2>`)
  const grouped = groupBy(report.results)
  for (const reg of REG_ORDER) {
    const items = grouped[reg]
    if (!items || items.length === 0) continue
    sections.push(`<h3>${esc(zh ? REGULATION_NAMES[reg].zh : REGULATION_NAMES[reg].en)}</h3>`)
    sections.push('<table class="controls"><thead><tr>'
      + `<th>${t('状态', 'Status')}</th><th>${t('控制项', 'Control')}</th><th>${t('条款', 'Article')}</th><th>${t('结论', 'Result')}</th></tr></thead><tbody>`)
    for (const r of items) {
      const st = STATUS[r.status]
      sections.push(`<tr><td><span class="badge ${st.cls}">${zh ? st.zh : st.en}</span></td>`
        + `<td>${esc(zh ? r.control.title_zh : r.control.title_en)}</td>`
        + `<td class="loc">${esc(r.control.article)}</td>`
        + `<td>${esc(zh ? r.detail_zh : r.detail_en)}</td></tr>`)
    }
    sections.push('</tbody></table>')
  }

  const disclaimer = t(
    '本报告由 ShellWard 合规网关自动生成，帮助评估并满足合规技术要求，不构成法律意见，亦不替代算法备案/定级备案/PIA 等主体责任。⚪ 待确认项需结合业务人工判定。',
    'Generated by ShellWard Compliance Gateway. Assists with technical compliance; not legal advice.')

  return `<!DOCTYPE html>
<html lang="${zh ? 'zh-CN' : 'en'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${t('AI 应用合规体检报告', 'AI Compliance Report')}</title>
<style>${CSS}</style>
</head>
<body>
<main>
  <header>
    <h1>🛡️ ${t('AI 应用合规体检报告', 'AI Application Compliance Report')}</h1>
    <p class="meta">${t('生成时间', 'Generated')}: ${esc(when)} UTC ｜ ${t('扫描目录', 'Scanned')}: <code>${esc(meta.root)}</code></p>
  </header>
  ${sections.join('\n')}
  <footer>${esc(disclaimer)}</footer>
</main>
</body>
</html>`
}

function groupBy(results: ControlResult[]): Record<Regulation, ControlResult[]> {
  const out = {} as Record<Regulation, ControlResult[]>
  for (const r of results) (out[r.control.regulation] ||= []).push(r)
  return out
}

/** HTML 转义，防止文件路径/详情里的特殊字符破坏结构 */
function esc(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

const CSS = `
:root{--ink:#1e293b;--muted:#64748b;--line:#e2e8f0;--bg:#f8fafc}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 24px;background:#fff}
header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:24px}
h1{font-size:24px;margin:0 0 6px}
h2{font-size:19px;margin:32px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:20px 0 8px;color:var(--muted)}
.meta{color:var(--muted);font-size:13px;margin:0}
code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:13px}
.score-card{display:flex;gap:28px;align-items:center;background:#f1f5f9;border-radius:12px;padding:24px}
.gauge{text-align:center;min-width:120px}
.gauge .score{font-size:44px;font-weight:700;color:var(--c)}
.gauge .score span{font-size:18px;color:var(--muted);font-weight:400}
.gauge .grade{font-size:28px;font-weight:700}
.summary{flex:1}
.bar{height:14px;background:#e2e8f0;border-radius:7px;overflow:hidden;margin-bottom:12px}
.bar .fill{height:100%}
.counts{list-style:none;display:flex;gap:18px;flex-wrap:wrap;padding:0;margin:0;font-size:14px}
.penalty{color:#dc2626;font-size:13px;margin:8px 0 0}
table{width:100%;border-collapse:collapse;margin:8px 0 4px;font-size:13.5px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f8fafc;font-weight:600;color:var(--muted)}
.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:#0f172a;white-space:nowrap}
.sev-critical{color:#dc2626;font-weight:600}.sev-high{color:#ea580c}.sev-medium{color:#d97706}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
.badge.pass{background:#dcfce7;color:#15803d}.badge.warn{background:#fef9c3;color:#a16207}
.badge.fail{background:#fee2e2;color:#b91c1c}.badge.manual{background:#e2e8f0;color:#475569}
.muted{color:var(--muted);font-size:13px}
.ok{color:#15803d;font-weight:600}
.migrate{margin:8px 0}
footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
@media print{body{background:#fff}main{max-width:none;padding:0}h2{break-after:avoid}table{break-inside:auto}tr{break-inside:avoid}}
`
