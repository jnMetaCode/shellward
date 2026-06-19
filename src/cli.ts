#!/usr/bin/env node
// src/cli.ts — ShellWard CLI 入口（零安装合规体检）
//
//   npx shellward            → 扫描当前项目，输出合规体检评分卡
//   npx shellward scan [dir] → 同上，可指定目录
//   npx shellward scan --json→ 输出 JSON（CI 用）
//   npx shellward mcp        → 启动 MCP 服务器（stdio，向后兼容）
//   npx shellward --help
//
// 设计目标：30 秒、零配置、出一张可截图的「你的项目」合规风险报告。

import { resolve } from 'path'
import { writeFileSync } from 'fs'
import { ShellWard } from './core/engine.js'
import { runProjectComplianceAudit } from './compliance/audit.js'
import { renderComplianceReport, renderProjectFindings } from './compliance/report.js'
import { resolveLocale } from './types.js'

const argv = process.argv.slice(2)
const wantsHelp = argv.includes('--help') || argv.includes('-h') || argv[0] === 'help'
const cmd = argv[0] && !argv[0].startsWith('-') ? argv[0] : 'scan'

async function main() {
  if (wantsHelp) {
    printHelp()
    return
  }

  if (cmd === 'mcp') {
    // 转发到 MCP 服务器（import 即启动 stdio 循环）
    await import('./mcp-server.js')
    return
  }

  if (cmd === 'scan') {
    runScan(argv.slice(1))
    return
  }

  console.error(`未知命令: ${cmd}\n`)
  printHelp()
  process.exit(2)
}

function runScan(args: string[]) {
  const json = args.includes('--json')
  const ci = args.includes('--ci')
  const outPath = flagValue(args, '--out')
  const dirArg = args.find(a => !a.startsWith('-'))
  const root = resolve(dirArg || process.cwd())

  // 用环境变量解析 locale；layers/mode 用默认（代表「采用 ShellWard 默认部署」的合规覆盖）
  const guard = new ShellWard({
    locale: (process.env.SHELLWARD_LOCALE as any) || 'auto',
    mode: (process.env.SHELLWARD_MODE as any) || 'enforce',
    autoCheckOnStartup: false,
  })
  const locale = resolveLocale(guard.config)
  const zh = locale === 'zh'

  const { report, scan } = runProjectComplianceAudit(guard.config, root)

  if (json) {
    process.stdout.write(JSON.stringify({
      root,
      score: report.score,
      grade: report.grade,
      summary: { passed: report.passed, warned: report.warned, failed: report.failed, manual: report.manual },
      projectScan: {
        filesScanned: scan.filesScanned,
        truncated: scan.truncated,
        counts: scan.counts,
        findings: scan.findings,
      },
      controls: report.results.map(r => ({
        id: r.control.id, regulation: r.control.regulation, status: r.status,
      })),
    }, null, 2) + '\n')
  } else {
    // 头条：项目实测风险（关于「你的项目」）+ 合规映射评分卡
    const body = [
      renderProjectFindings(scan, locale),
      renderComplianceReport(report, locale),
    ].join('\n')

    if (outPath) {
      const doc = `<!-- 扫描目录: ${root} -->\n\n` + body + '\n'
      writeFileSync(resolve(outPath), doc, 'utf-8')
      process.stdout.write(zh
        ? `✅ 合规报告已导出: ${resolve(outPath)}\n   得分 ${report.score}/100 [${report.grade}]，可存档用于备案/审计。\n`
        : `✅ Compliance report exported: ${resolve(outPath)}\n   Score ${report.score}/100 [${report.grade}].\n`)
    } else {
      const out = [
        zh ? `\n扫描目录: ${root}\n` : `\nScanned: ${root}\n`,
        body,
        '',
        zh
          ? '💡 这是只读扫描，未上传任何数据。要在运行时自动拦截风险，把 ShellWard 作为 MCP/插件接入你的 AI Agent。'
          : '💡 Read-only scan, nothing uploaded. To block these risks at runtime, integrate ShellWard as an MCP server/plugin in your AI agent.',
      ]
      process.stdout.write(out.join('\n') + '\n')
    }
  }

  // CI 模式：有 critical 项目发现则非零退出
  if (ci) {
    const criticals = scan.findings.filter(f => f.severity === 'critical').length
    if (criticals > 0) process.exit(1)
  }
}

/** 取 `--flag value` 或 `--flag=value` 的值 */
function flagValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag)
  if (i >= 0 && args[i + 1] && !args[i + 1].startsWith('-')) return args[i + 1]
  const eq = args.find(a => a.startsWith(flag + '='))
  return eq ? eq.slice(flag.length + 1) : undefined
}

function printHelp() {
  const lang = (process.env.SHELLWARD_LOCALE === 'en') ? 'en' : 'zh'
  if (lang === 'en') {
    console.log(`ShellWard — AI compliance gateway

Usage:
  shellward [scan] [dir]   Scan a project for compliance risks (default)
  shellward scan --json    Output JSON (for CI)
  shellward scan --ci      Exit non-zero if critical findings
  shellward scan --out f   Export the full report to a Markdown file
  shellward mcp            Start MCP server (stdio)
  shellward --help

Detects: overseas LLM endpoints (data-export risk), hardcoded secrets,
PII in files, .env permissions. Maps to CSL / PIPL / MLPS / cross-border / labeling.`)
  } else {
    console.log(`ShellWard — AI 合规网关

用法:
  shellward [scan] [目录]   扫描项目的合规风险（默认命令）
  shellward scan --json     输出 JSON（CI 用）
  shellward scan --ci       有 critical 发现时非零退出
  shellward scan --out 文件  导出完整报告为 Markdown（合规存档）
  shellward mcp             启动 MCP 服务器（stdio）
  shellward --help

检测: 境外大模型端点(数据出境)、硬编码密钥、文件中的个人信息、.env 权限。
映射到 网安法 / PIPL / 等保2.0 / 数据出境 / AI标识。`)
  }
}

main().catch(err => {
  console.error(`[ShellWard] ${err?.message || err}`)
  process.exit(1)
})
