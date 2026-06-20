// src/compliance/html-report.ts — HTML 合规报告（合规包）
//
// 终端输出给开发者看；这份 HTML 给法务/合规/测评机构看 —— 可在浏览器打开、
// 打印成 PDF、用于等保/PIPL 备案存档。自包含（内联 CSS、零外部依赖、无需联网）。
//
// 设计目标：专业、可信、克制——环形评分仪表、语义化状态药丸、severity 彩色标签、
// 卡片化分组、品牌色克制使用、清晰层级。

import { REGULATION_NAMES } from './regulations.js'
import type { Regulation } from './regulations.js'
import type { ComplianceReport, ControlResult, ControlStatus } from './audit.js'
import type { ProjectScanResult, FindingKind } from './project-scan.js'
import { suggestDomestic } from '../rules/domestic-alternatives.js'

const STATUS: Record<ControlStatus, { zh: string; en: string; cls: string }> = {
  pass: { zh: '合规', en: 'Pass', cls: 'pass' },
  warn: { zh: '部分', en: 'Partial', cls: 'warn' },
  fail: { zh: '不合规', en: 'Fail', cls: 'fail' },
  manual: { zh: '待确认', en: 'Review', cls: 'manual' },
}

const KIND: Record<FindingKind, { zh: string; en: string; icon: string }> = {
  overseas: { zh: '数据出境风险', en: 'Data export risk', icon: '🌐' },
  secret: { zh: '硬编码密钥', en: 'Hardcoded secret', icon: '🔑' },
  pii: { zh: '个人信息暴露', en: 'PII exposure', icon: '🪪' },
  'env-perm': { zh: '.env 权限', en: '.env permission', icon: '📂' },
}
const KIND_ORDER: FindingKind[] = ['overseas', 'secret', 'pii', 'env-perm']
const REG_ORDER: Regulation[] = ['CSL', 'PIPL', 'MLPS', 'CBDT', 'GENAI']

const GRADE: Record<string, { color: string; zh: string; en: string }> = {
  A: { color: '#16a34a', zh: '优秀', en: 'Excellent' },
  B: { color: '#65a30d', zh: '良好', en: 'Good' },
  C: { color: '#d97706', zh: '及格', en: 'Fair' },
  D: { color: '#dc2626', zh: '不及格', en: 'Poor' },
}
const SEV: Record<string, { zh: string; en: string }> = {
  critical: { zh: '严重', en: 'Critical' },
  high: { zh: '高', en: 'High' },
  medium: { zh: '中', en: 'Medium' },
}

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
  const g = GRADE[report.grade] || { color: '#475569', zh: report.grade, en: report.grade }
  const when = report.generatedAt.slice(0, 19).replace('T', ' ')

  const S: string[] = []

  // ===== 评分 Hero =====
  // 诚实原则：静态扫描下多数控制项不可验证，不展示"优秀/A"式合规结论，
  // 改以「风险发现数」为主指标，得分仅作"可观测项"的次要参考。
  const findingsN = scan.findings.length
  const gradeLabel = report.staticScan ? t('可观测项', 'observable') : t(g.zh, g.en)
  const verdict = report.staticScan
    ? (findingsN === 0
        ? { txt: t('未发现可观测风险', 'No observable risks'), c: '#16a34a', ic: '🟢' }
        : { txt: t(`发现 ${findingsN} 项风险`, `${findingsN} risk(s) found`), c: '#dc2626', ic: '🔴' })
    : { txt: t(g.zh, g.en), c: g.color, ic: '' }

  S.push(`
  <section class="hero">
    <div class="gauge" style="--p:${report.score};--c:${g.color}">
      <div class="gauge-in">
        <div class="gscore">${report.score}<small>/100</small></div>
        <div class="ggrade" style="color:${g.color}">${esc(report.grade)} · ${esc(gradeLabel)}</div>
      </div>
    </div>
    <div class="hero-side">
      <div class="verdict" style="--vc:${verdict.c}">${verdict.ic} ${esc(verdict.txt)}</div>
      <div class="stat-row">
        ${stat('pass', '🟢', t('合规', 'Pass'), report.passed)}
        ${stat('warn', '🟡', t('部分', 'Partial'), report.warned)}
        ${stat('fail', '🔴', t('不合规', 'Fail'), report.failed)}
        ${stat('manual', '⚪', t('待核验', 'Review'), report.manual)}
      </div>
      ${report.projectPenalty ? `<div class="penalty">⚠ ${t('含项目实测风险扣分', 'Includes project-scan penalty')} <b>−${report.projectPenalty}</b></div>` : ''}
      <p class="hero-note">${report.staticScan
        ? t(`⚠ 本次为静态扫描：已检查 ${report.filesScanned ?? scan.filesScanned} 个文件，仅评估可观测风险。<b>${report.manual} 项合规控制项未验证</b>（需部署 ShellWard 运行时或人工核验）——本报告不构成完整合规结论，得分仅供参考。`,
            `⚠ Static scan: checked ${report.filesScanned ?? scan.filesScanned} files for observable risk only. <b>${report.manual} controls unverified</b> — not a complete compliance verdict.`)
        : t('得分基于已部署运行时的合规评估。', 'Score based on deployed-runtime assessment.')}</p>
    </div>
  </section>`)

  // ===== 项目实测风险 =====
  S.push(sectionHead('🔍', t('项目实测风险', 'Project Scan Findings'),
    t(`已扫描 ${scan.filesScanned} 个文件${scan.truncated ? '（已达上限）' : ''} · 耗时 ${scan.durationMs ?? '?'}ms · 应用 ${scan.rulesChecked ?? '?'} 条检测规则`,
      `Scanned ${scan.filesScanned} files${scan.truncated ? ' (limit reached)' : ''} · ${scan.durationMs ?? '?'}ms · ${scan.rulesChecked ?? '?'} detection rules`)))

  if (scan.findings.length === 0) {
    // 空结果也要展示"检查过程"——逐项列出查了什么、均未命中，证明确实扫了
    S.push(`<div class="empty">🟢 ${t('逐项检查完成，未在可扫描文件中发现风险。', 'All checks passed — no risks found in scannable files.')}</div>`)
    S.push(`<table class="tbl checked"><tbody>
      <tr><td>🌐 ${t('境外大模型端点 + SDK 依赖', 'Overseas LLM endpoints + SDK deps')}</td><td class="muted">${t('OpenAI / Anthropic / Gemini / Cohere… 共 38 个特征', '38 signatures')}</td><td class="right ok">✓ ${t('0 命中', '0 hits')}</td></tr>
      <tr><td>🔑 ${t('硬编码密钥', 'Hardcoded secrets')}</td><td class="muted">${t('OpenAI/GitHub/AWS key、私钥、JWT、口令、连接串', 'OpenAI/GitHub/AWS/private key/JWT/password/conn-string')}</td><td class="right ok">✓ ${t('0 命中', '0 hits')}</td></tr>
      <tr><td>🪪 ${t('中文 PII + 国际 PII', 'Chinese + intl PII')}</td><td class="muted">${t('身份证(校验位)/手机号/银行卡(Luhn)/SSN/信用卡', 'CN ID(checksum)/mobile/UnionPay(Luhn)/SSN/credit card')}</td><td class="right ok">✓ ${t('0 命中', '0 hits')}</td></tr>
      <tr><td>📂 .env ${t('权限', 'permission')}</td><td class="muted">${t('含密钥的 .env 不应组/其他可读', '.env should not be group/other readable')}</td><td class="right ok">✓ ${t('正常', 'OK')}</td></tr>
    </tbody></table>`)
  } else {
    S.push('<div class="chips">')
    for (const k of KIND_ORDER) if (scan.counts[k] > 0) {
      S.push(`<span class="chip"><b>${scan.counts[k]}</b> ${KIND[k].icon} ${t(KIND[k].zh, KIND[k].en)}</span>`)
    }
    S.push('</div>')
    for (const kind of KIND_ORDER) {
      const items = scan.findings.filter(f => f.kind === kind)
      if (items.length === 0) continue
      S.push(`<h3 class="sub">${KIND[kind].icon} ${t(KIND[kind].zh, KIND[kind].en)} <span class="n">${items.length}</span></h3>`)
      S.push('<table class="tbl"><tbody>')
      for (const f of items) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file
        S.push(`<tr>
          <td class="loc"><code>${esc(loc)}</code></td>
          <td>${esc(f.detail)}</td>
          <td class="right">${sevPill(f.severity, zh)}</td></tr>`)
      }
      S.push('</tbody></table>')
    }
  }

  // ===== 境内合规替代建议 =====
  const overseas = scan.findings.filter(f => f.kind === 'overseas')
  if (overseas.length > 0) {
    S.push(sectionHead('✅', t('境内合规替代建议', 'Domestic Compliance Alternatives'),
      t('把数据出境风险变成可执行的迁移路径', 'Turn data-export risk into a migration path')))
    const seen = new Set<string>()
    const providers: { key: string; zh?: string; en?: string }[] = []
    for (const f of overseas) {
      const k = (f.endpointId || f.provider_en || f.provider_zh || '').toLowerCase()
      if (!k || seen.has(k)) continue
      seen.add(k)
      providers.push({ key: f.endpointId || f.provider_en || '', zh: f.provider_zh, en: f.provider_en })
    }
    S.push('<div class="migrate">')
    for (const p of providers) {
      const s = suggestDomestic(p.key, p.zh, p.en)
      const low = (zh ? s.difficulty_zh : s.difficulty_en).startsWith(zh ? '低' : 'Low')
      S.push(`<div class="mrow"><b>${esc(zh ? s.overseas_zh : s.overseas_en)}</b>
        <span class="mtag ${low ? 'low' : 'mid'}">${t('迁移', 'Migrate')}: ${esc(zh ? s.difficulty_zh : s.difficulty_en)}</span></div>`)
    }
    S.push('</div>')
    const alts = suggestDomestic(providers[0].key, providers[0].zh, providers[0].en).alternatives
    S.push('<table class="tbl alts"><thead><tr>'
      + `<th>${t('境内模型', 'Domestic model')}</th><th>${t('厂商', 'Vendor')}</th><th>${t('OpenAI 兼容 base_url', 'OpenAI-compatible base_url')}</th></tr></thead><tbody>`)
    for (const m of alts) {
      S.push(`<tr><td><b>${esc(zh ? m.name_zh : m.name_en)}</b></td><td class="muted">${esc(m.vendor_zh)}</td><td class="loc"><code>${esc(m.baseUrl)}</code></td></tr>`)
    }
    S.push('</tbody></table>')
    S.push(`<p class="note">💡 ${t('对使用 openai SDK 的项目：通常仅需把 base_url 与 api_key 换成上表任一境内模型即可，业务代码无需改动。',
      'For openai-SDK projects: usually just swap base_url + api_key — no code change.')}</p>`)
  }

  // ===== 控制项明细 =====
  S.push(sectionHead('📋', t('合规控制项明细', 'Compliance Controls'),
    t('按法规分组', 'By regulation')))
  if (report.staticScan && report.manual > 0) {
    S.push(`<div class="note manual-note">${t(
      `<b>⚪ 待核验 ≠ 不合规。</b> 下方 ${report.manual} 项是<b>运行时合规控制</b>（审计留存、内容过滤、注入拦截、数据外发管控等）——靠"看代码"的静态扫描判断不了，需把 ShellWard 接入你的 AI 应用（<code>npx shellward mcp</code> 或插件）作为运行时防护后才能验证，或人工核验。每项后面是"该做什么"。`,
      `<b>⚪ Review ≠ non-compliant.</b> The ${report.manual} items below are <b>runtime controls</b> a static scan cannot verify — deploy ShellWard as a runtime guard (<code>npx shellward mcp</code> / plugin) to validate them. Each row shows the remediation.`)}</div>`)
  }
  const grouped = groupBy(report.results)
  for (const reg of REG_ORDER) {
    const items = grouped[reg]
    if (!items || items.length === 0) continue
    const p = items.filter(r => r.status === 'pass').length
    const f = items.filter(r => r.status === 'fail').length
    S.push(`<div class="reg">
      <div class="reg-head"><span>${esc(zh ? REGULATION_NAMES[reg].zh : REGULATION_NAMES[reg].en)}</span>
        <span class="reg-mini">${p ? `<i class="d pass"></i>${p}` : ''}${f ? `<i class="d fail"></i>${f}` : ''}</span></div>
      <table class="tbl ctrl"><tbody>`)
    for (const r of items) {
      const st = STATUS[r.status]
      S.push(`<tr class="${st.cls}">
        <td class="st">${statusPill(r.status, zh)}</td>
        <td class="ttl"><b>${esc(zh ? r.control.title_zh : r.control.title_en)}</b><span class="art">${esc(r.control.article)}</span></td>
        <td class="${r.status === 'manual' ? 'faint' : ''}">${esc(zh ? r.detail_zh : r.detail_en)}</td></tr>`)
    }
    S.push('</tbody></table></div>')
  }

  const disclaimer = t(
    '本报告由 ShellWard 合规网关自动生成，帮助评估并满足合规技术要求，不构成法律意见，亦不替代算法备案/定级备案/PIA 等主体责任。⚪ 待确认项需结合业务人工判定。',
    'Generated by ShellWard Compliance Gateway. Assists with technical compliance; not legal advice. ⚪ items require manual review.')

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
    <div class="brand">🛡️ Shell<span>Ward</span> <em>${t('合规网关', 'Compliance Gateway')}</em></div>
    <h1>${t('AI 应用合规体检报告', 'AI Application Compliance Report')}</h1>
    <p class="meta">${t('生成', 'Generated')}: ${esc(when)} UTC&nbsp;&nbsp;·&nbsp;&nbsp;${t('扫描目录', 'Path')}: <code>${esc(meta.root)}</code></p>
  </header>
  ${S.join('\n')}
  <footer>${esc(disclaimer)}</footer>
</main>
</body>
</html>`
}

// ===== 小组件 =====

function stat(cls: string, icon: string, label: string, n: number): string {
  return `<div class="stat ${cls}"><div class="sn">${n}</div><div class="sl">${icon} ${label}</div></div>`
}

function sectionHead(icon: string, title: string, sub: string): string {
  return `<div class="shead"><h2>${icon} ${esc(title)}</h2><span>${esc(sub)}</span></div>`
}

function statusPill(s: ControlStatus, zh: boolean): string {
  const st = STATUS[s]
  return `<span class="pill ${st.cls}">${zh ? st.zh : st.en}</span>`
}

function sevPill(sev: string, zh: boolean): string {
  const s = SEV[sev] || { zh: sev, en: sev }
  return `<span class="sev ${sev}">${zh ? s.zh : s.en}</span>`
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
:root{
  --ink:#0f172a;--muted:#64748b;--faint:#94a3b8;--line:#eaeef4;--bg:#eef1f6;--card:#fff;
  --brand:#cb0000;
  --pass:#16a34a;--pass-bg:#dcfce7;--warn:#b45309;--warn-bg:#fef3c7;
  --fail:#dc2626;--fail-bg:#fee2e2;--manual:#64748b;--manual-bg:#eef2f7;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  -webkit-font-smoothing:antialiased}
main{max-width:880px;margin:28px auto;background:var(--card);border-radius:16px;
  box-shadow:0 1px 3px rgba(15,23,42,.06),0 12px 32px rgba(15,23,42,.07);overflow:hidden}
header{padding:30px 36px 22px;background:linear-gradient(180deg,#fafbfd,#fff);border-bottom:1px solid var(--line)}
.brand{font-size:13px;font-weight:700;color:var(--ink);letter-spacing:.2px}
.brand span{color:var(--brand)}
.brand em{font-style:normal;color:var(--faint);font-weight:500;margin-left:4px}
h1{font-size:25px;margin:10px 0 6px;letter-spacing:-.3px}
.meta{color:var(--muted);font-size:13px;margin:0}
.meta code{background:#f1f5f9;padding:1px 6px;border-radius:5px;font-size:12px}
section,.reg{padding:0 36px}

/* Hero 评分 */
.hero{display:flex;gap:32px;align-items:center;margin:26px 36px;padding:26px 28px;
  background:linear-gradient(135deg,#f8fafc,#f1f5f9);border:1px solid var(--line);border-radius:14px}
.gauge{--p:0;--c:#475569;flex:none;width:148px;height:148px;border-radius:50%;
  background:conic-gradient(var(--c) calc(var(--p)*1%),#e4e9f1 0);
  display:grid;place-items:center;box-shadow:inset 0 0 0 1px rgba(15,23,42,.04)}
.gauge-in{width:116px;height:116px;border-radius:50%;background:#fff;display:flex;flex-direction:column;
  align-items:center;justify-content:center;box-shadow:0 2px 8px rgba(15,23,42,.08)}
.gscore{font-size:42px;font-weight:800;line-height:1;letter-spacing:-1px}
.gscore small{font-size:15px;font-weight:500;color:var(--faint)}
.ggrade{font-size:14px;font-weight:700;margin-top:6px}
.hero-side{flex:1;min-width:0}
.verdict{font-size:17px;font-weight:800;color:var(--vc);margin:0 0 12px}
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.stat{background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px 12px;text-align:center}
.stat .sn{font-size:22px;font-weight:800;line-height:1}
.stat .sl{font-size:12px;color:var(--muted);margin-top:3px;white-space:nowrap}
.stat.pass .sn{color:var(--pass)}.stat.warn .sn{color:var(--warn)}
.stat.fail .sn{color:var(--fail)}.stat.manual .sn{color:var(--manual)}
.penalty{margin-top:12px;display:inline-block;background:var(--fail-bg);color:var(--fail);
  font-size:12.5px;font-weight:600;padding:5px 12px;border-radius:8px}
.hero-note{margin:12px 0 0;font-size:12.5px;color:var(--muted);line-height:1.55}

/* 段标题 */
.shead{display:flex;align-items:baseline;gap:12px;margin:34px 36px 14px;
  padding-bottom:10px;border-bottom:2px solid var(--line)}
.shead h2{font-size:18px;margin:0;font-weight:700}
.shead span{font-size:12.5px;color:var(--faint)}
.sub{font-size:14px;font-weight:700;color:var(--ink);margin:18px 36px 8px}
.sub .n{display:inline-block;background:#eef2f7;color:var(--muted);font-size:12px;
  padding:0 8px;border-radius:999px;margin-left:4px;font-weight:600}
.empty{margin:8px 36px;padding:16px 18px;background:var(--pass-bg);color:var(--pass);
  border-radius:10px;font-weight:600;font-size:14px}
.checked td.ok{color:var(--pass);font-weight:700}
.checked td:first-child{font-weight:600;white-space:nowrap}

/* chips 概览 */
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:6px 36px 4px}
.chip{background:#f1f5f9;border:1px solid var(--line);border-radius:999px;
  padding:5px 13px;font-size:13px;color:var(--muted)}
.chip b{color:var(--ink);font-size:14px;margin-right:2px}

/* 表格 */
.tbl{width:calc(100% - 72px);margin:4px 36px 6px;border-collapse:separate;border-spacing:0;font-size:13.5px}
.tbl td,.tbl th{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}
.tbl th{background:#f8fafc;color:var(--muted);font-weight:600;font-size:12.5px;
  border-bottom:1px solid #e2e8f0}
.tbl tbody tr:hover{background:#fafbfd}
.tbl .right{text-align:right;white-space:nowrap}
.tbl .muted{color:var(--muted)}
.tbl .faint{color:var(--faint);font-size:13px}
.loc code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
  background:#f1f5f9;color:#0f172a;padding:2px 7px;border-radius:5px;
  white-space:normal;word-break:break-all;overflow-wrap:anywhere}
.alts th:first-child,.alts td:first-child{width:120px}
/* 发现表三列布局：位置≤40% 可换行、说明占主、严重度窄列不挤 */
table.tbl td.loc{width:34%;max-width:300px}
table.tbl td.right{width:64px}

/* severity 标签 */
.sev{display:inline-block;font-size:11.5px;font-weight:700;padding:2px 9px;border-radius:999px}
.sev.critical{background:#fee2e2;color:#b91c1c}
.sev.high{background:#ffedd5;color:#c2410c}
.sev.medium{background:#fef3c7;color:#b45309}

/* 状态药丸 */
.pill{display:inline-block;font-size:12px;font-weight:700;padding:3px 11px;border-radius:999px;white-space:nowrap}
.pill.pass{background:var(--pass-bg);color:var(--pass)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}
.pill.fail{background:var(--fail-bg);color:var(--fail)}
.pill.manual{background:var(--manual-bg);color:var(--manual)}

/* 境内替代 */
.migrate{margin:6px 36px 10px;display:flex;flex-direction:column;gap:8px}
.mrow{display:flex;align-items:center;gap:12px;font-size:14px}
.mtag{font-size:12px;font-weight:600;padding:3px 10px;border-radius:8px}
.mtag.low{background:var(--pass-bg);color:var(--pass)}
.mtag.mid{background:var(--warn-bg);color:var(--warn)}
.note{margin:8px 36px 4px;font-size:12.5px;color:var(--muted);background:#f8fafc;
  border-left:3px solid var(--brand);padding:10px 14px;border-radius:0 8px 8px 0}
.manual-note{margin:8px 36px 12px;font-size:13px;color:#475569;background:#eff6ff;
  border-left:3px solid #3b82f6;line-height:1.6}
.manual-note code{background:#dbeafe;padding:1px 6px;border-radius:5px}

/* 法规分组 */
.reg{margin:14px 36px;padding:0;border:1px solid var(--line);border-radius:12px;overflow:hidden}
.reg-head{display:flex;justify-content:space-between;align-items:center;
  padding:11px 16px;background:#f8fafc;font-weight:700;font-size:14px;border-bottom:1px solid var(--line)}
.reg-mini{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--muted);font-weight:600}
.reg-mini .d{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px;vertical-align:middle}
.reg-mini .d.pass{background:var(--pass)}.reg-mini .d.fail{background:var(--fail)}
.reg .tbl{width:100%;margin:0}
.reg .tbl td{padding:10px 16px}
.reg .tbl tr:last-child td{border-bottom:0}
.ctrl .st{width:78px}
.ctrl .ttl{width:210px}
.ctrl .ttl b{display:block;font-weight:600;font-size:13.5px}
.ctrl .art{display:block;color:var(--faint);font-size:11.5px;margin-top:2px}
.ctrl tr.fail{background:#fef6f6}

footer{margin-top:30px;padding:20px 36px 30px;border-top:1px solid var(--line);
  color:var(--faint);font-size:11.5px;line-height:1.6;background:#fafbfd}

@media(max-width:640px){
  main{margin:0;border-radius:0}
  .hero{flex-direction:column;text-align:center;margin:18px}
  .stat-row{grid-template-columns:repeat(2,1fr)}
  section,.shead,.sub,.chips,.tbl,.migrate,.note,.reg{margin-left:16px;margin-right:16px}
  .tbl{width:calc(100% - 32px)}
}
@media print{
  body{background:#fff}
  main{box-shadow:none;margin:0;max-width:none;border-radius:0}
  .hero{background:#f8fafc}
  .reg,.tbl tbody tr{break-inside:avoid}
  h2,.shead{break-after:avoid}
}
`
