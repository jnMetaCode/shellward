// src/commands/check-updates.ts — /check-updates: check versions + remote vulnerability DB

import { execSync } from 'child_process'
import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import type { ShellWardConfig } from '../types.js'
import { resolveLocale } from '../types.js'
import { checkForUpdate, fetchVulnDB, compareVersions, type VulnEntry } from '../update-check.js'

// Local fallback vulnerability database (used when remote fetch fails)
// Contains only CVE-assigned vulnerabilities as minimum baseline
const LOCAL_VULNS = [
  {
    affectedBelow: '1.0.111',
    severity: 'HIGH' as const,
    id: 'CVE-2025-59536',
    description_zh: '远程代码执行：恶意仓库通过 Hooks 和 MCP Server 在信任提示前执行任意命令 (CVSS 8.7)',
    description_en: 'RCE via Hooks and MCP Server bypass — arbitrary shell execution before trust dialog (CVSS 8.7)',
  },
  {
    affectedBelow: '2.0.65',
    severity: 'MEDIUM' as const,
    id: 'CVE-2026-21852',
    description_zh: 'API 密钥泄露：恶意仓库通过 settings.json 设置 ANTHROPIC_BASE_URL 窃取用户 API Key (CVSS 5.3)',
    description_en: 'API key exfiltration via ANTHROPIC_BASE_URL in settings.json before trust prompt (CVSS 5.3)',
  },
  {
    affectedBelow: '2026.2.7',
    severity: 'HIGH' as const,
    id: 'GHSA-ff64-7w26-62rf',
    description_zh: '沙箱逃逸：通过 settings.json 持久化配置注入',
    description_en: 'Sandbox escape via persistent configuration injection in settings.json',
  },
]

export function registerCheckUpdatesCommand(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  api.registerCommand({
    name: 'check-updates',
    description: locale === 'zh'
      ? '🔄 检查版本更新和已知漏洞（支持远程漏洞库）'
      : '🔄 Check for updates and known vulnerabilities (remote vuln DB)',
    acceptsArgs: false,
    handler: async () => {
      const zh = locale === 'zh'
      const lines: string[] = []

      lines.push(zh ? '🔄 **版本与漏洞检查**' : '🔄 **Version & Vulnerability Check**')
      lines.push('')

      // 1. Get OpenClaw version
      let openclawVersion = 'unknown'
      try {
        const out = execSync('openclaw --version 2>&1', { timeout: 5000 }).toString().trim()
        const match = out.match(/(\d{4}\.\d+\.\d+)/)
        if (match) openclawVersion = match[1]
      } catch { /* skip */ }

      lines.push(zh
        ? `### OpenClaw 版本: ${openclawVersion}`
        : `### OpenClaw Version: ${openclawVersion}`)
      lines.push('')

      // 2. Check ShellWard version + available update
      let shellwardVersion = 'unknown'
      try {
        const pkgPath = join(__dirname, '../../package.json')
        if (existsSync(pkgPath)) {
          const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
          shellwardVersion = pkg.version || 'unknown'
        }
      } catch { /* skip */ }

      lines.push(zh
        ? `### ShellWard 版本: ${shellwardVersion}`
        : `### ShellWard Version: ${shellwardVersion}`)

      // Check for ShellWard update from npm
      try {
        const updateInfo = await checkForUpdate(shellwardVersion)
        if (updateInfo?.updateAvailable) {
          lines.push(zh
            ? `  🆕 **新版本 v${updateInfo.latest} 可用！** 运行 \`openclaw plugins update shellward\` 更新`
            : `  🆕 **v${updateInfo.latest} available!** Run \`openclaw plugins update shellward\` to update`)
        } else if (updateInfo) {
          lines.push(zh ? '  ✅ 已是最新版本' : '  ✅ Up to date')
        }
      } catch { /* skip */ }
      lines.push('')

      // 3. Check known vulnerabilities (remote DB with local fallback)
      lines.push(zh ? '### 已知漏洞检查' : '### Known Vulnerability Check')

      let vulnDB: VulnEntry[] = LOCAL_VULNS
      let alerts: { id: string; severity: string; date: string; description_zh: string; description_en: string }[] = []
      let dbSource = 'local'
      try {
        const remote = await fetchVulnDB()
        if (remote.vulns.length > 0) {
          vulnDB = remote.vulns
          dbSource = 'remote'
        }
        alerts = remote.alerts || []
      } catch { /* use local */ }

      lines.push(zh
        ? `  数据源: ${dbSource === 'remote' ? `远程漏洞库 (GitHub) — ${vulnDB.length} 条记录` : '本地内置数据库'}`
        : `  Source: ${dbSource === 'remote' ? `Remote vuln DB (GitHub) — ${vulnDB.length} entries` : 'Local built-in database'}`)

      if (openclawVersion === 'unknown') {
        lines.push(zh
          ? '  ⚠️ 无法确定 OpenClaw 版本，请手动检查'
          : '  ⚠️ Cannot determine OpenClaw version, please check manually')
      } else {
        const affected = vulnDB.filter(v => compareVersions(openclawVersion, v.affectedBelow) < 0)
        if (affected.length === 0) {
          lines.push(zh
            ? '  ✅ 当前版本未发现已知漏洞'
            : '  ✅ No known vulnerabilities for current version')
        } else {
          for (const vuln of affected) {
            const icon = vuln.severity === 'CRITICAL' ? '🔴' : '🟡'
            const desc = zh ? vuln.description_zh : vuln.description_en
            lines.push(`  ${icon} **${vuln.id}** [${vuln.severity}]: ${desc}`)
            lines.push(zh
              ? `     影响版本: < ${vuln.affectedBelow} — 请升级`
              : `     Affected: < ${vuln.affectedBelow} — please upgrade`)
          }
        }
      }

      // Supply chain alerts
      if (alerts.length > 0) {
        lines.push('')
        lines.push(zh ? '### 供应链安全警告' : '### Supply Chain Alerts')
        for (const alert of alerts) {
          const icon = alert.severity === 'CRITICAL' ? '🔴' : '🟡'
          const desc = zh ? alert.description_zh : alert.description_en
          lines.push(`  ${icon} **${alert.id}** [${alert.date}]: ${desc}`)
        }
      }
      lines.push('')

      // 4. Check Node.js version
      lines.push(zh ? '### 运行环境' : '### Runtime Environment')
      try {
        const nodeVer = process.version
        const major = parseInt(nodeVer.slice(1))
        if (major < 22) {
          lines.push(zh
            ? `  ⚠️ Node.js ${nodeVer} — OpenClaw 要求 >= 22.12，请升级`
            : `  ⚠️ Node.js ${nodeVer} — OpenClaw requires >= 22.12, please upgrade`)
        } else {
          lines.push(zh
            ? `  ✅ Node.js ${nodeVer}`
            : `  ✅ Node.js ${nodeVer}`)
        }
      } catch { /* skip */ }

      lines.push(`  ${zh ? '平台' : 'Platform'}: ${process.platform} ${process.arch}`)
      lines.push('')

      // 5. Recommendations
      lines.push('---')
      lines.push(zh
        ? '💡 **建议**: 定期运行 `/check-updates` 检查，及时升级到最新版本'
        : '💡 **Tip**: Run `/check-updates` regularly, upgrade to latest versions promptly')
      lines.push(zh
        ? '📖 关注 OpenClaw 安全公告: https://github.com/nicepkg/openclaw/security'
        : '📖 Follow OpenClaw security advisories: https://github.com/nicepkg/openclaw/security')

      return { text: lines.join('\n') }
    },
  })
}
