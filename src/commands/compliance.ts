// src/commands/compliance.ts — /compliance 命令：一键合规体检报告
//
// 月1 获客钩子的命令形态。扫一遍配置 + 环境 + 审计日志 + 出境端点，
// 输出网安法/PIPL/等保/数据出境/AI标识 的红黄绿合规评分卡。

import type { ShellWardConfig } from '../types.js'
import { resolveLocale } from '../types.js'
import { runComplianceAudit } from '../compliance/audit.js'
import { renderComplianceReport } from '../compliance/report.js'

export function registerComplianceCommand(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  api.registerCommand({
    name: 'compliance',
    description: locale === 'zh'
      ? '📋 AI 应用合规体检（网安法/PIPL/等保/数据出境/AI标识）'
      : '📋 AI compliance health check (CSL/PIPL/MLPS/Cross-border/Labeling)',
    acceptsArgs: false,
    handler: () => {
      const report = runComplianceAudit(config)
      return { text: renderComplianceReport(report, locale) }
    },
  })
}
