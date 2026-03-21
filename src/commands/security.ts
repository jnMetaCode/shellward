// src/commands/security.ts — /security command: full security status overview

import { readFileSync, statSync, existsSync, readdirSync } from 'fs'
import { join } from 'path'
import { execSync } from 'child_process'
import { getHomeDir } from '../utils.js'
import type { ShellWardConfig } from '../types.js'
import { resolveLocale } from '../types.js'

const LOG_DIR = join(getHomeDir(), '.openclaw', 'shellward')
const LOG_FILE = join(LOG_DIR, 'audit.jsonl')

export function registerSecurityCommand(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  api.registerCommand({
    name: 'security',
    description: locale === 'zh'
      ? '🛡️ ShellWard 安全状态总览'
      : '🛡️ ShellWard security status overview',
    acceptsArgs: false,
    handler: () => {
      const lines: string[] = []
      const zh = locale === 'zh'

      lines.push(zh ? '🛡️ **ShellWard 安全状态报告**' : '🛡️ **ShellWard Security Status Report**')
      lines.push('')

      // 1. Layer status
      lines.push(zh ? '## 防御层状态' : '## Defense Layers')
      const layers = [
        ['L1 Prompt Guard', config.layers.promptGuard],
        ['L2 Output Scanner', config.layers.outputScanner],
        ['L3 Tool Blocker', config.layers.toolBlocker],
        ['L4 Input Auditor', config.layers.inputAuditor],
        ['L5 Security Gate', config.layers.securityGate],
        ['L6 Outbound Guard', config.layers.outboundGuard],
        ['L7 Data Flow Guard', config.layers.dataFlowGuard],
        ['L8 Session Guard', config.layers.sessionGuard],
      ]
      for (const [name, enabled] of layers) {
        lines.push(`  ${enabled ? '✅' : '❌'} ${name}`)
      }
      lines.push(`  ${zh ? '模式' : 'Mode'}: **${config.mode}**`)
      lines.push(`  ${zh ? '注入阈值' : 'Injection threshold'}: **${config.injectionThreshold}**`)
      lines.push('')

      // 2. Audit log stats
      lines.push(zh ? '## 审计日志' : '## Audit Log')
      try {
        const stat = statSync(LOG_FILE)
        const sizeMB = (stat.size / 1024 / 1024).toFixed(2)
        lines.push(`  ${zh ? '文件' : 'File'}: ${LOG_FILE}`)
        lines.push(`  ${zh ? '大小' : 'Size'}: ${sizeMB} MB`)

        // Count recent events
        const content = readFileSync(LOG_FILE, 'utf-8')
        const allLines = content.trim().split('\n').filter(Boolean)
        const total = allLines.length
        let blocks = 0
        let audits = 0
        let criticals = 0
        for (const line of allLines) {
          if (line.includes('"action":"block"')) blocks++
          if (line.includes('"action":"audit"')) audits++
          if (line.includes('"level":"CRITICAL"')) criticals++
        }
        lines.push(`  ${zh ? '总事件' : 'Total events'}: ${total}`)
        lines.push(`  ${zh ? '拦截' : 'Blocked'}: ${blocks} | ${zh ? '审计' : 'Audited'}: ${audits} | ${zh ? '严重' : 'Critical'}: ${criticals}`)
      } catch {
        lines.push(zh ? '  ⚠️ 日志文件不存在' : '  ⚠️ Log file not found')
      }
      lines.push('')

      // 3. Quick system security checks
      lines.push(zh ? '## 系统安全快检' : '## Quick System Security Check')

      // Check exposed ports
      try {
        const listening = execSync('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null', { timeout: 5000 }).toString()
        const openClawPort = listening.includes(':19000') || listening.includes(':19001')
        lines.push(openClawPort
          ? (zh ? '  ⚠️ OpenClaw 端口正在监听 (建议限制访问)' : '  ⚠️ OpenClaw port is listening (restrict access)')
          : (zh ? '  ✅ OpenClaw 端口未暴露' : '  ✅ OpenClaw port not exposed'))
      } catch {
        lines.push(zh ? '  ℹ️ 无法检查端口状态' : '  ℹ️ Cannot check port status')
      }

      // Check .env exposure
      const envFile = join(process.cwd(), '.env')
      if (existsSync(envFile)) {
        try {
          const mode = statSync(envFile).mode & 0o777
          lines.push(mode > 0o600
            ? (zh ? `  ⚠️ .env 文件权限过宽 (${mode.toString(8)})，建议 chmod 600` : `  ⚠️ .env file permissions too open (${mode.toString(8)}), suggest chmod 600`)
            : (zh ? '  ✅ .env 文件权限正常' : '  ✅ .env file permissions OK'))
        } catch { /* skip */ }
      }

      // Check if running as root
      if (process.getuid && process.getuid() === 0) {
        lines.push(zh
          ? '  ⚠️ 正在以 root 运行 (建议使用普通用户 + 容器隔离)'
          : '  ⚠️ Running as root (use non-root user + container isolation)')
      } else {
        lines.push(zh ? '  ✅ 非 root 运行' : '  ✅ Not running as root')
      }

      lines.push('')
      lines.push(zh
        ? '💡 使用 `/audit` 查看日志, `/harden` 执行安全加固, `/scan-plugins` 扫描插件'
        : '💡 Use `/audit` for logs, `/harden` for hardening, `/scan-plugins` to scan plugins')

      return { text: lines.join('\n') }
    },
  })
}
