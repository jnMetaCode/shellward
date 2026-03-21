// src/commands/index.ts — Register all ShellWard commands

import type { ShellWardConfig } from '../types.js'
import { resolveLocale } from '../types.js'
import { registerSecurityCommand } from './security.js'
import { registerAuditCommand } from './audit.js'
import { registerHardenCommand } from './harden.js'
import { registerScanPluginsCommand } from './scan-plugins.js'
import { registerCheckUpdatesCommand } from './check-updates.js'
import { registerUpgradeOpenClawCommand } from './upgrade-openclaw.js'

export function registerAllCommands(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  // Register individual commands
  registerSecurityCommand(api, config)
  registerAuditCommand(api, config)
  registerHardenCommand(api, config)
  registerScanPluginsCommand(api, config)
  registerCheckUpdatesCommand(api, config)
  registerUpgradeOpenClawCommand(api, config)

  // Register /cg shortcut with help
  api.registerCommand({
    name: 'cg',
    description: locale === 'zh'
      ? '🛡️ ShellWard 安全命令帮助'
      : '🛡️ ShellWard security command help',
    acceptsArgs: false,
    handler: () => ({
      text: locale === 'zh' ? `🛡️ **ShellWard 快捷命令**

| 命令 | 说明 |
|------|------|
| \`/security\` | 安全状态总览（防御层、审计统计、系统检查） |
| \`/audit [数量] [过滤]\` | 查看审计日志 (过滤: block/audit/critical/high) |
| \`/harden\` | 安全扫描 · \`/harden fix\` 自动修复权限 |
| \`/scan-plugins\` | 扫描已安装插件的安全风险 |
| \`/check-updates\` | 检查 OpenClaw 版本和已知漏洞 |
| \`/upgrade-openclaw\` | 一键升级 OpenClaw · \`/upgrade-openclaw yes\` 直接执行 |

**当前防御层 (8层):**
L1 提示注入 · L2 输出审计 · L3 工具拦截 · L4 注入检测
L5 安全门 · L6 回复审计 · L7 数据流监控 · L8 会话安全`
        : `🛡️ **ShellWard Quick Commands**

| Command | Description |
|---------|-------------|
| \`/security\` | Security status overview (layers, audit stats, system checks) |
| \`/audit [count] [filter]\` | View audit log (filter: block/audit/critical/high) |
| \`/harden\` | Security scan · \`/harden fix\` to auto-fix permissions |
| \`/scan-plugins\` | Scan installed plugins for security risks |
| \`/check-updates\` | Check OpenClaw version and known vulnerabilities |
| \`/upgrade-openclaw\` | Upgrade OpenClaw · \`/upgrade-openclaw yes\` to execute |

**Active Defense Layers (8):**
L1 Prompt Guard · L2 Output Scanner · L3 Tool Blocker · L4 Input Auditor
L5 Security Gate · L6 Outbound Guard · L7 Data Flow Guard · L8 Session Guard`,
    }),
  })
}
