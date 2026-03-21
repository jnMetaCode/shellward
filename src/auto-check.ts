// src/auto-check.ts — 启动时自动安全检查，减少人为操作
// 异步执行，不阻塞启动；发现问题时通过 logger 告警

import { execSync } from 'child_process'
import { existsSync, readFileSync, readdirSync } from 'fs'
import { join } from 'path'
import { getHomeDir } from './utils.js'
import { fetchVulnDB, compareVersions } from './update-check.js'

const OPENCLAW_DIR = join(getHomeDir(), '.openclaw')

export interface AutoCheckResult {
  openclawVulns: { id: string; severity: string; description: string }[]
  pluginRisks: { plugin: string; risk: string }[]
  mcpRisks: { config: string; risk: string }[]
  rootWarning: boolean
}

const SUSPICIOUS_PATTERNS = [
  { pattern: /eval\s*\(/, name: 'eval()' },
  { pattern: /\/dev\/tcp|nc\s+-e|ncat/, name: 'reverse shell' },
  { pattern: /webhook|exfil|callback.*http/i, name: 'data exfil' },
]

/**
 * 获取 OpenClaw 版本
 */
function getOpenClawVersion(): string {
  try {
    const out = execSync('openclaw --version 2>&1', { timeout: 5000 }).toString().trim()
    const match = out.match(/(\d{4}\.\d+\.\d+|\d+\.\d+\.\d+)/)
    return match ? match[1] : 'unknown'
  } catch {
    return 'unknown'
  }
}

/**
 * 检查 OpenClaw 是否受已知漏洞影响
 */
async function checkOpenClawVulns(version: string, locale: 'zh' | 'en' = 'en'): Promise<{ id: string; severity: string; description: string }[]> {
  const vulns: { id: string; severity: string; description: string }[] = []
  try {
    const { vulns: db } = await fetchVulnDB()
    const list = db.length > 0 ? db : [
      { affectedBelow: '1.0.111', severity: 'HIGH' as const, id: 'CVE-2025-59536', description_zh: 'RCE via Hooks/MCP', description_en: 'RCE via Hooks/MCP' },
      { affectedBelow: '2.0.65', severity: 'MEDIUM' as const, id: 'CVE-2026-21852', description_zh: 'API Key exfil', description_en: 'API Key exfil' },
    ]
    for (const v of list) {
      if (version !== 'unknown' && compareVersions(version, v.affectedBelow) < 0) {
        vulns.push({
          id: v.id,
          severity: v.severity || 'MEDIUM',
          description: locale === 'zh'
            ? ((v as any).description_zh || (v as any).description_en || v.id)
            : ((v as any).description_en || (v as any).description_zh || v.id),
        })
      }
    }
  } catch { /* ignore */ }
  return vulns
}

/**
 * 快速扫描插件中的高风险模式
 */
function scanPluginsQuick(): { plugin: string; risk: string }[] {
  const risks: { plugin: string; risk: string }[] = []
  const dirs = [
    join(OPENCLAW_DIR, 'extensions'),
    join(OPENCLAW_DIR, 'plugins'),
  ]
  for (const dir of dirs) {
    if (!existsSync(dir)) continue
    try {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name)
        if (name.startsWith('.')) continue
        try {
          const files = readdirSync(p)
          for (const f of files) {
            if (!/\.(ts|js)$/.test(f)) continue
            const content = readFileSync(join(p, f), 'utf-8').slice(0, 50000)
            for (const { pattern, name: riskName } of SUSPICIOUS_PATTERNS) {
              if (pattern.test(content)) {
                risks.push({ plugin: name, risk: riskName })
                break
              }
            }
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  }
  return risks
}

/**
 * 扫描 MCP 配置中的可疑项
 */
function scanMcpConfig(): { config: string; risk: string }[] {
  const risks: { config: string; risk: string }[] = []
  const configPaths = [
    join(OPENCLAW_DIR, 'mcp.json'),
    join(OPENCLAW_DIR, 'config', 'mcp.json'),
    join(OPENCLAW_DIR, 'settings.json'),
  ]
  for (const p of configPaths) {
    if (!existsSync(p)) continue
    try {
      const content = readFileSync(p, 'utf-8')
      if (/webhook|exfil|callback|pastebin|requestbin/i.test(content)) {
        risks.push({ config: p, risk: 'suspicious URL in config' })
      }
      if (/command.*:.*["'](?:curl|wget|nc)\s/i.test(content)) {
        risks.push({ config: p, risk: 'network command in MCP' })
      }
    } catch { /* skip */ }
  }
  return risks
}

/**
 * 执行全部自动检查，返回结果（供启动时告警用）
 */
export async function runAutoCheck(locale: 'zh' | 'en' = 'en'): Promise<AutoCheckResult> {
  const ocVersion = getOpenClawVersion()
  const [openclawVulns, pluginRisks, mcpRisks] = await Promise.all([
    checkOpenClawVulns(ocVersion, locale),
    Promise.resolve(scanPluginsQuick()),
    Promise.resolve(scanMcpConfig()),
  ])
  const rootWarning = typeof process.getuid === 'function' && process.getuid() === 0
  return { openclawVulns, pluginRisks, mcpRisks, rootWarning }
}

/**
 * 启动时执行检查，发现问题时通过 logger 告警
 */
export function runAutoCheckOnStartup(logger: { warn: (s: string) => void }, locale: 'zh' | 'en'): void {
  runAutoCheck(locale).then(result => {
    const zh = locale === 'zh'
    const lines: string[] = []

    if (result.openclawVulns.length > 0) {
      lines.push(zh ? '⚠️ OpenClaw 存在已知漏洞:' : '⚠️ OpenClaw has known vulnerabilities:')
      for (const v of result.openclawVulns) {
        lines.push(`  ${v.id} [${v.severity}]: ${v.description}`)
      }
      lines.push(zh ? '  请运行 /check-updates 查看详情并升级' : '  Run /check-updates for details and upgrade')
    }

    if (result.pluginRisks.length > 0) {
      lines.push(zh ? '⚠️ 插件扫描发现可疑模式:' : '⚠️ Plugin scan found suspicious patterns:')
      for (const r of result.pluginRisks.slice(0, 3)) {
        lines.push(`  ${r.plugin}: ${r.risk}`)
      }
      if (result.pluginRisks.length > 3) {
        lines.push(zh ? `  ... 共 ${result.pluginRisks.length} 项` : `  ... ${result.pluginRisks.length} total`)
      }
      lines.push(zh ? '  请运行 /scan-plugins 查看详情' : '  Run /scan-plugins for details')
    }

    if (result.mcpRisks.length > 0) {
      lines.push(zh ? '⚠️ MCP 配置存在可疑项:' : '⚠️ Suspicious items in MCP config:')
      for (const r of result.mcpRisks) {
        lines.push(`  ${r.config}: ${r.risk}`)
      }
    }

    if (result.rootWarning) {
      lines.push(zh ? '⚠️ 正在以 root 运行，建议使用普通用户' : '⚠️ Running as root, consider using non-root user')
    }

    if (lines.length > 0) {
      logger.warn((zh ? '[ShellWard] 自动安全检查:\n' : '[ShellWard] Auto security check:\n') + lines.join('\n'))
    }
  }).catch(() => { /* 静默失败，不阻塞 */ })
}
