// src/commands/audit.ts — /audit command: view recent audit log entries

import { readFileSync, statSync } from 'fs'
import { join } from 'path'
import { getHomeDir } from '../utils.js'
import type { ShellWardConfig } from '../types.js'
import { resolveLocale } from '../types.js'

const LOG_FILE = join(getHomeDir(), '.openclaw', 'shellward', 'audit.jsonl')

export function registerAuditCommand(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  api.registerCommand({
    name: 'audit',
    description: locale === 'zh'
      ? '📋 查看 ShellWard 审计日志 (用法: /audit [数量] [block|audit|critical])'
      : '📋 View ShellWard audit log (usage: /audit [count] [block|audit|critical])',
    acceptsArgs: true,
    handler: (ctx: any) => {
      const zh = locale === 'zh'
      const args = (ctx.args || '').trim().split(/\s+/).filter(Boolean)

      // Parse args: count and optional filter
      let count = 20
      let filter = ''
      for (const arg of args) {
        if (/^\d+$/.test(arg)) {
          count = Math.min(parseInt(arg), 100)
        } else {
          filter = arg.toLowerCase()
        }
      }

      try {
        statSync(LOG_FILE)
      } catch {
        return { text: zh ? '⚠️ 审计日志文件不存在，尚无安全事件记录。' : '⚠️ Audit log not found. No security events recorded yet.' }
      }

      const content = readFileSync(LOG_FILE, 'utf-8')
      let lines = content.trim().split('\n').filter(Boolean)

      // Apply filter
      if (filter === 'block') {
        lines = lines.filter(l => l.includes('"action":"block"'))
      } else if (filter === 'audit') {
        lines = lines.filter(l => l.includes('"action":"audit"'))
      } else if (filter === 'redact') {
        lines = lines.filter(l => l.includes('"action":"redact"'))
      } else if (filter === 'critical') {
        lines = lines.filter(l => l.includes('"level":"CRITICAL"'))
      } else if (filter === 'high') {
        lines = lines.filter(l => l.includes('"level":"HIGH"') || l.includes('"level":"CRITICAL"'))
      }

      // Get last N entries
      const recent = lines.slice(-count)

      if (recent.length === 0) {
        return { text: zh ? '✅ 没有匹配的审计事件。' : '✅ No matching audit events.' }
      }

      const header = zh
        ? `📋 **审计日志** (最近 ${recent.length} 条${filter ? `, 过滤: ${filter}` : ''})`
        : `📋 **Audit Log** (last ${recent.length} entries${filter ? `, filter: ${filter}` : ''})`

      const formatted = recent.map(line => {
        try {
          const e = JSON.parse(line)
          const icon = e.action === 'block' ? '🚫' : e.action === 'audit' ? '📋' : e.action === 'redact' ? '🔒' : e.level === 'CRITICAL' ? '🔴' : 'ℹ️'
          const time = e.ts?.slice(11, 19) || '??:??:??'
          return `${icon} \`${time}\` **${e.layer}** ${e.action}: ${e.detail?.slice(0, 80) || ''}${e.pattern ? ` [${e.pattern}]` : ''}`
        } catch {
          return line.slice(0, 100)
        }
      })

      return { text: `${header}\n\n${formatted.join('\n')}` }
    },
  })
}
