// src/init.ts — `shellward init`：一条命令把 ShellWard 接入已安装的 AI 工具（MCP 运行时防护）
//
// 把"扫描 → 运行时防护"的部署摩擦降到一条命令：自动探测 Claude Desktop / Cursor /
// Claude Code / Windsurf 的 MCP 配置，安全地加入 shellward 条目（备份、合并、不覆盖）。
// 这是「安装按钮」的正确形态——只对已知配置文件操作、改前备份、可 --dry-run 预览。

import { readFileSync, writeFileSync, existsSync, copyFileSync, mkdirSync } from 'fs'
import { join, dirname } from 'path'
import { homedir } from 'os'

/** 标准 MCP 接入条目：零安装，npx 拉取已发布的 shellward-mcp */
export const SHELLWARD_MCP_ENTRY = {
  command: 'npx',
  args: ['-y', '-p', 'shellward', 'shellward-mcp'],
}

export interface InitTarget {
  name: string
  path: string
  /** 配置里放 MCP 服务器的字段名（绝大多数是 mcpServers） */
  key: string
  /** 工具未安装时是否允许新建配置文件 */
  createIfMissing?: boolean
}

/** 已知 AI 工具的 MCP 配置位置（跨平台） */
export function knownTargets(home = homedir()): InitTarget[] {
  const appData = process.env.APPDATA || join(home, 'AppData', 'Roaming')
  const claudeDesktop =
    process.platform === 'darwin' ? join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
    : process.platform === 'win32' ? join(appData, 'Claude', 'claude_desktop_config.json')
    : join(home, '.config', 'Claude', 'claude_desktop_config.json')
  return [
    { name: 'Claude Desktop', path: claudeDesktop, key: 'mcpServers', createIfMissing: true },
    { name: 'Cursor', path: join(home, '.cursor', 'mcp.json'), key: 'mcpServers', createIfMissing: true },
    { name: 'Claude Code', path: join(home, '.claude.json'), key: 'mcpServers' },
    { name: 'Windsurf', path: join(home, '.codeium', 'windsurf', 'mcp_config.json'), key: 'mcpServers' },
  ]
}

export type MergeResult =
  | { status: 'added' | 'updated'; config: any }
  | { status: 'unchanged'; config: any }

/**
 * 纯合并：把 shellward 条目并入配置对象。已存在且相同→unchanged；不同→updated；没有→added。
 * 不破坏其它 MCP 服务器条目。
 */
export function mergeShellward(config: any, key: string): MergeResult {
  const cfg = config && typeof config === 'object' ? config : {}
  const servers = cfg[key] && typeof cfg[key] === 'object' ? cfg[key] : {}
  const existing = servers.shellward
  const same = existing && JSON.stringify(existing) === JSON.stringify(SHELLWARD_MCP_ENTRY)
  if (same) return { status: 'unchanged', config: cfg }
  const status = existing ? 'updated' : 'added'
  cfg[key] = { ...servers, shellward: { ...SHELLWARD_MCP_ENTRY } }
  return { status, config: cfg }
}

export interface InitOutcome {
  name: string
  path: string
  result: 'added' | 'updated' | 'unchanged' | 'skipped' | 'error'
  detail?: string
}

/** 执行接入：探测→读取→合并→备份→写回。dryRun 仅预览不写。 */
export function runInit(opts: { dryRun?: boolean; home?: string } = {}): InitOutcome[] {
  const targets = knownTargets(opts.home)
  const out: InitOutcome[] = []
  for (const t of targets) {
    const exists = existsSync(t.path)
    if (!exists && !t.createIfMissing) {
      out.push({ name: t.name, path: t.path, result: 'skipped', detail: '未安装/无配置' })
      continue
    }
    try {
      let config: any = {}
      if (exists) {
        const raw = readFileSync(t.path, 'utf-8').trim()
        config = raw ? JSON.parse(raw) : {}
      }
      const merged = mergeShellward(config, t.key)
      if (merged.status === 'unchanged') {
        out.push({ name: t.name, path: t.path, result: 'unchanged', detail: '已接入' })
        continue
      }
      if (!opts.dryRun) {
        if (exists) copyFileSync(t.path, t.path + '.shellward.bak') // 改前备份
        else mkdirSync(dirname(t.path), { recursive: true })
        writeFileSync(t.path, JSON.stringify(merged.config, null, 2) + '\n')
      }
      out.push({ name: t.name, path: t.path, result: merged.status, detail: opts.dryRun ? '预览（未写入）' : (exists ? '已加入（原文件已备份 .bak）' : '已新建配置') })
    } catch (e: any) {
      out.push({ name: t.name, path: t.path, result: 'error', detail: e?.message || String(e) })
    }
  }
  return out
}
