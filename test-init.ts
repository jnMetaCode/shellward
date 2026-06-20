#!/usr/bin/env npx tsx
// test-init.ts — `shellward init` 接入逻辑测试（纯合并 + 临时 home 实跑，不碰真实配置）

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs'
import { join, dirname } from 'path'
import { tmpdir } from 'os'
import { mergeShellward, runInit, knownTargets, SHELLWARD_MCP_ENTRY } from './src/init'

let passed = 0, failed = 0
function test(name: string, cond: boolean, detail?: string) {
  if (cond) { passed++; console.log(`  ✅ ${name}`) }
  else { failed++; console.log(`  ❌ ${name}${detail ? ' — ' + detail : ''}`) }
}

console.log('\n========== ShellWard init 接入测试 ==========\n')

// === 纯合并逻辑 ===
console.log('--- mergeShellward ---')
{
  const a = mergeShellward({}, 'mcpServers')
  test('空配置 → added', a.status === 'added' && !!a.config.mcpServers.shellward)
  test('写入标准条目', JSON.stringify(a.config.mcpServers.shellward) === JSON.stringify(SHELLWARD_MCP_ENTRY))

  const withOther = { mcpServers: { other: { command: 'x' } } }
  const b = mergeShellward(withOther, 'mcpServers')
  test('保留已有其它 MCP 服务器', !!b.config.mcpServers.other && !!b.config.mcpServers.shellward)

  const c = mergeShellward(b.config, 'mcpServers')
  test('幂等：第二次 → unchanged', c.status === 'unchanged')

  const stale = { mcpServers: { shellward: { command: 'old' } } }
  const d = mergeShellward(stale, 'mcpServers')
  test('旧条目 → updated 并修正', d.status === 'updated' && d.config.mcpServers.shellward.command === 'npx')

  // 不破坏配置里的其它顶层字段
  const e = mergeShellward({ theme: 'dark', mcpServers: {} }, 'mcpServers')
  test('保留其它顶层字段', e.config.theme === 'dark')
}

// === 临时 home 实跑（含备份、新建、跳过未安装） ===
console.log('\n--- runInit（临时 home） ---')
{
  const home = mkdtempSync(join(tmpdir(), 'sw-init-'))
  try {
    // 造一个"已安装"的 Claude Desktop 配置（带已有条目，验证备份+合并）
    const targets = knownTargets(home)
    const claude = targets.find(t => t.name === 'Claude Desktop')!
    mkdirSync(dirname(claude.path), { recursive: true })
    writeFileSync(claude.path, JSON.stringify({ mcpServers: { foo: { command: 'bar' } } }))

    const out = runInit({ home, dryRun: false })
    const cl = out.find(o => o.name === 'Claude Desktop')!
    test('Claude Desktop → added', cl.result === 'added')
    test('原配置已备份 .bak', existsSync(claude.path + '.shellward.bak'))
    const written = JSON.parse(readFileSync(claude.path, 'utf-8'))
    test('合并后含 shellward 且保留 foo', !!written.mcpServers.shellward && !!written.mcpServers.foo)

    // Claude Code (~/.claude.json) 不存在且 createIfMissing=false → 跳过
    const cc = out.find(o => o.name === 'Claude Code')!
    test('未安装的工具被跳过（不乱建文件）', cc.result === 'skipped')

    // 再跑一次 → unchanged（幂等）
    const out2 = runInit({ home, dryRun: false })
    test('重复 init → unchanged', out2.find(o => o.name === 'Claude Desktop')!.result === 'unchanged')

    // dry-run 不写入
    const home2 = mkdtempSync(join(tmpdir(), 'sw-init2-'))
    try {
      const t2 = knownTargets(home2).find(t => t.name === 'Cursor')!
      runInit({ home: home2, dryRun: true })
      test('dry-run 不创建文件', !existsSync(t2.path))
    } finally { rmSync(home2, { recursive: true, force: true }) }
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
}

console.log(`\n========== init 测试: ${passed} 通过, ${failed} 失败 ==========\n`)
if (failed > 0) process.exit(1)
