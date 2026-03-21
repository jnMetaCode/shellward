// src/commands/harden.ts — /harden command: one-click security hardening

import { existsSync, statSync, chmodSync, readFileSync, readdirSync } from 'fs'
import { join } from 'path'
import { execSync } from 'child_process'
import type { ShellWardConfig } from '../types.js'
import { resolveLocale } from '../types.js'

import { getHomeDir } from '../utils.js'
const HOME = getHomeDir()

export function registerHardenCommand(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  api.registerCommand({
    name: 'harden',
    description: locale === 'zh'
      ? '🔒 一键安全加固 (权限修复、凭证扫描、端口检查)'
      : '🔒 One-click security hardening (permissions, credentials, ports)',
    acceptsArgs: true,
    handler: (ctx: any) => {
      const zh = locale === 'zh'
      const args = (ctx.args || '').trim().toLowerCase()
      const dryRun = args !== 'fix'

      const lines: string[] = []
      const issues: string[] = []
      const fixed: string[] = []

      lines.push(zh ? '🔒 **安全加固扫描**' : '🔒 **Security Hardening Scan**')
      if (dryRun) {
        lines.push(zh
          ? '_(扫描模式 — 使用 `/harden fix` 自动修复)_'
          : '_(scan mode — use `/harden fix` to auto-fix)_')
      }
      lines.push('')

      // === 1. File Permission Checks ===
      lines.push(zh ? '### 文件权限检查' : '### File Permission Checks')

      const sensitiveFiles = [
        ['.env', 0o600],
        ['.env.local', 0o600],
        ['.env.production', 0o600],
        ['.ssh/id_rsa', 0o600],
        ['.ssh/id_ed25519', 0o600],
        ['.ssh/config', 0o600],
        ['.aws/credentials', 0o600],
        ['.npmrc', 0o600],
        ['.git-credentials', 0o600],
        ['.openclaw/openclaw.json', 0o600],
      ] as const

      for (const [rel, target] of sensitiveFiles) {
        const full = join(HOME, rel)
        if (!existsSync(full)) continue
        try {
          const stat = statSync(full)
          const current = stat.mode & 0o777
          if (current > target) {
            const msg = zh
              ? `⚠️ ${rel}: 权限 ${current.toString(8)} → 建议 ${target.toString(8)}`
              : `⚠️ ${rel}: permissions ${current.toString(8)} → should be ${target.toString(8)}`
            issues.push(msg)
            lines.push(`  ${msg}`)

            if (!dryRun) {
              try {
                chmodSync(full, target)
                fixed.push(rel)
                lines.push(zh ? `    ✅ 已修复` : `    ✅ Fixed`)
              } catch {
                lines.push(zh ? `    ❌ 修复失败（权限不足）` : `    ❌ Fix failed (permission denied)`)
              }
            }
          } else {
            lines.push(zh ? `  ✅ ${rel}: ${current.toString(8)}` : `  ✅ ${rel}: ${current.toString(8)}`)
          }
        } catch { /* skip */ }
      }
      lines.push('')

      // === 2. Plaintext Credential Scan ===
      lines.push(zh ? '### 明文凭证扫描' : '### Plaintext Credential Scan')

      const credPatterns = [
        /(?:api[_-]?key|api[_-]?token|access[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}/i,
        /sk-[a-zA-Z0-9]{20,}/,
        /AKIA[0-9A-Z]{16}/,
        /ghp_[A-Za-z0-9_]{36,}/,
        /password\s*[=:]\s*['"]?\S{6,}/i,
      ]

      const envFiles = ['.env', '.env.local', '.env.production', '.bashrc', '.zshrc', '.bash_profile']
      let credFound = 0
      for (const rel of envFiles) {
        const full = join(HOME, rel)
        if (!existsSync(full)) continue
        try {
          const content = readFileSync(full, 'utf-8')
          for (const pat of credPatterns) {
            if (pat.test(content)) {
              credFound++
              const msg = zh
                ? `⚠️ ${rel}: 发现明文凭证（建议使用密钥管理工具）`
                : `⚠️ ${rel}: plaintext credentials found (use a secret manager)`
              issues.push(msg)
              lines.push(`  ${msg}`)
              break
            }
          }
        } catch { /* skip */ }
      }
      if (credFound === 0) {
        lines.push(zh ? '  ✅ 未发现明文凭证' : '  ✅ No plaintext credentials found')
      }
      lines.push('')

      // === 3. Network Exposure ===
      lines.push(zh ? '### 网络暴露检查' : '### Network Exposure Check')
      try {
        const listening = execSync('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null', { timeout: 5000 }).toString()
        const dangerPorts = [
          ['19000', 'OpenClaw Gateway'],
          ['19001', 'OpenClaw Dev'],
          ['3000', 'Dev Server'],
          ['8080', 'HTTP Alt'],
          ['5432', 'PostgreSQL'],
          ['3306', 'MySQL'],
          ['6379', 'Redis'],
          ['27017', 'MongoDB'],
        ]
        let portIssues = 0
        for (const [port, name] of dangerPorts) {
          // Check if listening on 0.0.0.0 (all interfaces)
          const allInterfaces = listening.includes(`0.0.0.0:${port}`) || listening.includes(`:::${port}`)
          if (allInterfaces) {
            portIssues++
            const msg = zh
              ? `⚠️ ${name} (${port}) 监听在所有接口 — 建议绑定 127.0.0.1`
              : `⚠️ ${name} (${port}) listening on all interfaces — bind to 127.0.0.1`
            issues.push(msg)
            lines.push(`  ${msg}`)
          }
        }
        if (portIssues === 0) {
          lines.push(zh ? '  ✅ 未发现危险端口暴露' : '  ✅ No dangerous port exposure detected')
        }
      } catch {
        lines.push(zh ? '  ℹ️ 无法检查网络状态' : '  ℹ️ Cannot check network status')
      }
      lines.push('')

      // === 4. Running as root ===
      lines.push(zh ? '### 运行权限' : '### Runtime Privileges')
      if (process.getuid && process.getuid() === 0) {
        const msg = zh
          ? '⚠️ 以 root 身份运行 — 强烈建议使用普通用户 + 容器隔离'
          : '⚠️ Running as root — strongly recommend non-root user + container isolation'
        issues.push(msg)
        lines.push(`  ${msg}`)
      } else {
        lines.push(zh ? '  ✅ 非 root 运行' : '  ✅ Not running as root')
      }

      // Check if Docker available
      try {
        execSync('which docker 2>/dev/null', { timeout: 3000 })
        lines.push(zh ? '  ✅ Docker 可用（可用于容器隔离）' : '  ✅ Docker available (for container isolation)')
      } catch {
        lines.push(zh ? '  ℹ️ Docker 未安装（建议安装以支持容器隔离）' : '  ℹ️ Docker not installed (recommended for isolation)')
      }
      lines.push('')

      // === 5. One-click scripts ===
      lines.push(zh ? '### 一键安全脚本' : '### One-click Security Scripts')

      // Dockerfile
      lines.push(zh ? '**容器隔离** — 复制以下 Dockerfile:' : '**Container isolation** — copy this Dockerfile:')
      lines.push('```dockerfile')
      lines.push('FROM node:22-slim')
      lines.push('RUN useradd -m -s /bin/bash openclaw')
      lines.push('USER openclaw')
      lines.push('WORKDIR /home/openclaw')
      lines.push('RUN npm install -g openclaw')
      lines.push('COPY .env .env')
      lines.push('EXPOSE 19000')
      lines.push('CMD ["openclaw", "agent", "--local"]')
      lines.push('```')
      lines.push(zh
        ? '运行: `docker build -t openclaw-safe . && docker run --rm -it openclaw-safe`'
        : 'Run: `docker build -t openclaw-safe . && docker run --rm -it openclaw-safe`')
      lines.push('')

      // Firewall
      lines.push(zh ? '**防火墙限制** — 仅允许必要出站:' : '**Firewall** — allow only necessary outbound:')
      lines.push('```bash')
      lines.push(zh ? '# 只允许 HTTPS 出站（API 调用），禁止其他出站' : '# Allow only HTTPS outbound (API calls), block everything else')
      lines.push('sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT')
      lines.push('sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT')
      lines.push('sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT  # DNS')
      lines.push('sudo iptables -A OUTPUT -o lo -j ACCEPT               # localhost')
      lines.push('sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')
      lines.push('sudo iptables -A OUTPUT -j LOG --log-prefix "BLOCKED: "')
      lines.push('sudo iptables -A OUTPUT -j DROP')
      lines.push('```')
      lines.push(zh
        ? '⚠️ 执行前请确认不会影响其他服务'
        : '⚠️ Review before applying — may affect other services')
      lines.push('')

      // === Summary ===
      lines.push('---')
      if (issues.length === 0) {
        lines.push(zh ? '✅ **安全检查通过！未发现问题。**' : '✅ **All checks passed! No issues found.**')
      } else {
        lines.push(zh
          ? `⚠️ **发现 ${issues.length} 个安全问题**${fixed.length > 0 ? `，已自动修复 ${fixed.length} 个` : ''}`
          : `⚠️ **Found ${issues.length} security issues**${fixed.length > 0 ? `, auto-fixed ${fixed.length}` : ''}`)
        if (dryRun && issues.some(i => i.includes('权限') || i.includes('permissions'))) {
          lines.push(zh
            ? '💡 使用 `/harden fix` 自动修复文件权限问题'
            : '💡 Use `/harden fix` to auto-fix file permission issues')
        }
      }

      return { text: lines.join('\n') }
    },
  })
}
