// src/commands/upgrade-openclaw.ts — 一键升级 OpenClaw，减少手动操作

import { execSync } from 'child_process'
import type { ShellWardConfig } from '../types.js'
import { resolveLocale } from '../types.js'

export function registerUpgradeOpenClawCommand(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  api.registerCommand({
    name: 'upgrade-openclaw',
    description: locale === 'zh'
      ? '⬆️ 升级 OpenClaw 到最新版本（一键执行）'
      : '⬆️ Upgrade OpenClaw to latest (one-click)',
    acceptsArgs: true,
    handler: (ctx: any) => {
      const zh = locale === 'zh'
      const args = (ctx.args || '').trim().toLowerCase()
      const doUpgrade = args === 'yes' || args === 'y' || args === '--yes'

      let currentVer = 'unknown'
      try {
        const out = execSync('openclaw --version 2>&1', { timeout: 5000 }).toString()
        const m = out.match(/(\d{4}\.\d+\.\d+|\d+\.\d+\.\d+)/)
        if (m) currentVer = m[1]
      } catch { /* skip */ }

      const cmd = 'npm update -g openclaw'
      const lines: string[] = []

      if (doUpgrade) {
        try {
          execSync(cmd, { stdio: 'inherit', timeout: 120000 })
          const newOut = execSync('openclaw --version 2>&1', { timeout: 5000 }).toString()
          const newM = newOut.match(/(\d{4}\.\d+\.\d+|\d+\.\d+\.\d+)/)
          const newVer = newM ? newM[1] : 'unknown'
          lines.push(zh ? `✅ 升级完成！当前版本: ${newVer}` : `✅ Upgrade done! Current version: ${newVer}`)
        } catch (e: any) {
          lines.push(zh ? `❌ 升级失败: ${e?.message || e}` : `❌ Upgrade failed: ${e?.message || e}`)
          lines.push(zh ? `请手动执行: \`${cmd}\`` : `Run manually: \`${cmd}\``)
        }
      } else {
        lines.push(zh ? `当前版本: ${currentVer}` : `Current version: ${currentVer}`)
        lines.push('')
        lines.push(zh ? '**一键升级**（复制执行）:' : '**One-click upgrade** (copy & run):')
        lines.push('```bash')
        lines.push(cmd)
        lines.push('```')
        lines.push('')
        lines.push(zh
          ? '或在 OpenClaw 中执行: `/upgrade-openclaw yes` 自动升级'
          : 'Or run in OpenClaw: `/upgrade-openclaw yes` to auto-upgrade')
      }

      return { text: lines.join('\n') }
    },
  })
}
