// src/commands/scan-plugins.ts — /scan-plugins: scan installed plugins for security risks

import { existsSync, readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import type { ShellWardConfig } from '../types'
import { resolveLocale } from '../types'

const HOME = process.env.HOME || '~'
const OPENCLAW_DIR = join(HOME, '.openclaw')

// Known suspicious patterns in plugin code
const SUSPICIOUS_PATTERNS = [
  { pattern: /eval\s*\(/, name: 'eval()', risk: 'code injection' },
  { pattern: /child_process|execSync|spawnSync|exec\(/, name: 'shell exec', risk: 'command execution' },
  { pattern: /\/dev\/tcp|nc\s+-e|ncat/, name: 'reverse shell', risk: 'remote access' },
  { pattern: /fetch\s*\([^)]*(?:webhook|exfil|callback)/, name: 'data exfiltration', risk: 'data leak' },
  { pattern: /process\.env\.[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)/i, name: 'env secret access', risk: 'credential access' },
  { pattern: /writeFileSync.*(?:\.ssh|\.env|\.aws|\.npmrc)/, name: 'sensitive file write', risk: 'credential tampering' },
  { pattern: /crypto\.createHash|Buffer\.from.*base64/, name: 'crypto/encoding', risk: 'possible obfuscation' },
  { pattern: /https?:\/\/(?!(?:github\.com|npmjs\.com|registry\.npmjs\.org))[^\s'"]+/g, name: 'external URL', risk: 'data exfiltration' },
]

export function registerScanPluginsCommand(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  api.registerCommand({
    name: 'scan-plugins',
    description: locale === 'zh'
      ? '🔍 扫描已安装插件的安全风险'
      : '🔍 Scan installed plugins for security risks',
    acceptsArgs: false,
    handler: () => {
      const zh = locale === 'zh'
      const lines: string[] = []

      lines.push(zh ? '🔍 **插件安全扫描报告**' : '🔍 **Plugin Security Scan Report**')
      lines.push('')

      // Find installed plugins
      const pluginDirs: { name: string; path: string }[] = []

      // Check global extensions
      const extensionsDir = join(OPENCLAW_DIR, 'extensions')
      if (existsSync(extensionsDir)) {
        try {
          for (const name of readdirSync(extensionsDir)) {
            const p = join(extensionsDir, name)
            if (statSync(p).isDirectory()) {
              pluginDirs.push({ name, path: p })
            }
          }
        } catch { /* skip */ }
      }

      // Check linked plugins
      const pluginsDir = join(OPENCLAW_DIR, 'plugins')
      if (existsSync(pluginsDir)) {
        try {
          for (const name of readdirSync(pluginsDir)) {
            const p = join(pluginsDir, name)
            pluginDirs.push({ name, path: p })
          }
        } catch { /* skip */ }
      }

      if (pluginDirs.length === 0) {
        lines.push(zh ? 'ℹ️ 未发现已安装的第三方插件。' : 'ℹ️ No third-party plugins found.')
        return { text: lines.join('\n') }
      }

      lines.push(zh
        ? `${zh ? '发现' : 'Found'} ${pluginDirs.length} ${zh ? '个插件' : 'plugins'}`
        : `Found ${pluginDirs.length} plugins`)
      lines.push('')

      let totalRisks = 0

      for (const plugin of pluginDirs) {
        const risks: string[] = []

        // 1. Check for package.json
        const pkgPath = join(plugin.path, 'package.json')
        let pkg: any = null
        if (existsSync(pkgPath)) {
          try {
            pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
          } catch { /* skip */ }
        }

        // 2. Check dependencies count (more deps = more supply chain risk)
        if (pkg) {
          const depCount = Object.keys(pkg.dependencies || {}).length
          if (depCount > 20) {
            risks.push(zh
              ? `⚠️ 依赖过多 (${depCount} 个) — 供应链攻击风险`
              : `⚠️ Too many deps (${depCount}) — supply chain risk`)
          }

          // Check for suspicious scripts
          const scripts = pkg.scripts || {}
          for (const [key, val] of Object.entries(scripts)) {
            if (/curl|wget|eval|nc\s/.test(String(val))) {
              risks.push(zh
                ? `🔴 可疑脚本: scripts.${key}`
                : `🔴 Suspicious script: scripts.${key}`)
            }
          }
        }

        // 3. Scan source files for suspicious patterns
        const srcFiles = collectSourceFiles(plugin.path, 3) // max depth 3
        for (const file of srcFiles) {
          try {
            const content = readFileSync(file, 'utf-8')
            for (const rule of SUSPICIOUS_PATTERNS) {
              // Use fresh regex to avoid lastIndex state issues with global patterns
              const regex = new RegExp(rule.pattern.source, rule.pattern.flags)
              if (regex.test(content)) {
                const relPath = file.replace(plugin.path + '/', '')
                risks.push(zh
                  ? `⚠️ ${relPath}: ${rule.name} (${rule.risk})`
                  : `⚠️ ${relPath}: ${rule.name} (${rule.risk})`)
              }
            }
          } catch { /* skip */ }
        }

        // 4. Check if plugin has signature/checksum
        const hasSignature = existsSync(join(plugin.path, 'SIGNATURE')) || existsSync(join(plugin.path, '.signature'))
        if (!hasSignature) {
          risks.push(zh ? 'ℹ️ 无签名验证文件' : 'ℹ️ No signature file')
        }

        // Output plugin report
        const icon = risks.filter(r => r.startsWith('🔴')).length > 0 ? '🔴'
          : risks.filter(r => r.startsWith('⚠️')).length > 0 ? '⚠️' : '✅'

        lines.push(`### ${icon} ${plugin.name}`)
        if (pkg) {
          lines.push(`  v${pkg.version || '?'} | ${pkg.author || 'unknown author'} | ${Object.keys(pkg.dependencies || {}).length} deps`)
        }

        if (risks.length === 0) {
          lines.push(zh ? '  ✅ 未发现安全风险' : '  ✅ No security risks found')
        } else {
          for (const risk of risks) {
            lines.push(`  ${risk}`)
            totalRisks++
          }
        }
        lines.push('')
      }

      // Summary
      lines.push('---')
      if (totalRisks === 0) {
        lines.push(zh ? '✅ **所有插件扫描通过**' : '✅ **All plugins passed scan**')
      } else {
        lines.push(zh
          ? `⚠️ **发现 ${totalRisks} 个潜在风险** — 请审查标记的插件`
          : `⚠️ **${totalRisks} potential risks found** — review flagged plugins`)
        lines.push(zh
          ? '💡 建议: 仅从可信渠道安装插件，定期运行 `/scan-plugins` 检查'
          : '💡 Tip: Only install plugins from trusted sources, run `/scan-plugins` regularly')
      }

      return { text: lines.join('\n') }
    },
  })
}

function collectSourceFiles(dir: string, maxDepth: number, depth = 0): string[] {
  if (depth > maxDepth) return []
  const files: string[] = []
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        files.push(...collectSourceFiles(full, maxDepth, depth + 1))
      } else if (/\.(ts|js|mjs|cjs)$/.test(entry.name)) {
        files.push(full)
      }
    }
  } catch { /* skip */ }
  return files
}
