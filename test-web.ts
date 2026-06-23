#!/usr/bin/env npx tsx
// test-web.ts — web 扫描服务端到端集成测试（启真实 http 服务，打全部端点）

import { spawn } from 'child_process'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

let passed = 0, failed = 0
function test(name: string, cond: boolean, detail?: string) {
  if (cond) { passed++; console.log(`  ✅ ${name}`) }
  else { failed++; console.log(`  ❌ ${name}${detail ? ' — ' + detail : ''}`) }
}

async function waitUp(url: string, ms = 8000): Promise<boolean> {
  const t0 = Date.now()
  while (Date.now() - t0 < ms) {
    try { const r = await fetch(url); if (r.ok) return true } catch { /* retry */ }
    await new Promise(r => setTimeout(r, 200))
  }
  return false
}

function startServer(args: string[]): Promise<any> {
  const child = spawn('node', ['dist/cli.js', 'web', ...args], { stdio: 'ignore' })
  return Promise.resolve(child)
}

async function main() {
  console.log('\n========== ShellWard Web 服务集成测试 ==========\n')

  // ---- 本地模式 ----
  console.log('--- 本地模式 (web --local) ---')
  const localPort = 8211
  const localSrv = await startServer(['--local', '--port', String(localPort)])
  const base = `http://localhost:${localPort}`
  const up = await waitUp(base + '/')
  test('服务启动并响应', up)
  if (up) {
    const home = await (await fetch(base + '/')).text()
    test('首页含路径栏(无上传弹框)', home.includes('pathbar') && home.includes('id="dirs"'))
    test('首页含 URL 入口', home.includes('公开仓库地址'))

    // 目录浏览器：列子目录（零上传）
    const browse = await (await fetch(base + '/browse?dir=' + encodeURIComponent(tmpdir()))).json() as any
    test('/browse 返回当前目录与子目录列表', typeof browse.current === 'string' && Array.isArray(browse.dirs))
    test('/browse 不列出 node_modules', !browse.dirs.includes('node_modules'))

    // 模拟浏览器上传（客户端读文件夹后发的 JSON）
    const payload = {
      root: 'myproj',
      files: [
        { path: 'myproj/package.json', content: '{"dependencies":{"openai":"^4"}}' },
        { path: 'myproj/app.ts', content: 'const k="sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq"\nconst phone="13912345678"' },
      ],
    }
    const upl = await fetch(base + '/scan-files', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
    test('上传扫描返回 200', upl.status === 200, `status=${upl.status}`)
    const uhtml = await upl.text()
    test('上传报告是完整 HTML', uhtml.startsWith('<!DOCTYPE html>'))
    test('上传报告含 openai 依赖发现', uhtml.includes('openai'))
    test('上传报告含密钥发现', uhtml.includes('硬编码') || uhtml.includes('密钥'))
    test('上传报告含手机号发现', uhtml.includes('手机号'))

    // 空上传
    const empty = await fetch(base + '/scan-files', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files: [] }) })
    test('空上传返回 400', empty.status === 400, `status=${empty.status}`)

    // 路径穿越防护
    const eviltmp = mkdtempSync(join(tmpdir(), 'sw-evil-'))
    const evil = await fetch(base + '/scan-files', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ root: 'x', files: [{ path: '../../../../' + eviltmp.replace(/^\//, '') + '/PWNED', content: 'x' }] }) })
    await evil.text()
    let pwned = false
    try { require('fs').statSync(join(eviltmp, 'PWNED')); pwned = true } catch { /* good */ }
    test('路径穿越被挡（未写出目标文件）', !pwned)
    rmSync(eviltmp, { recursive: true, force: true })

    // 本地路径扫描
    const proj = mkdtempSync(join(tmpdir(), 'sw-proj-'))
    writeFileSync(join(proj, 'package.json'), '{"dependencies":{"@anthropic-ai/sdk":"^0.2"}}')
    const pathScan = await fetch(base + '/scan?path=' + encodeURIComponent(proj))
    test('本地路径扫描返回 200', pathScan.status === 200, `status=${pathScan.status}`)
    test('本地路径扫描含 Anthropic 发现', (await pathScan.text()).includes('Anthropic'))
    rmSync(proj, { recursive: true, force: true })

    // 非法仓库 URL
    const bad = await fetch(base + '/scan?repo=' + encodeURIComponent('http://evil.com/a/b'))
    test('非法 URL 返回 400', bad.status === 400, `status=${bad.status}`)
  }
  try { localSrv.kill() } catch {}

  // ---- 公网模式 ----
  console.log('\n--- 公网模式 (web) ---')
  const pubPort = 8212
  const pubSrv = await startServer([String(pubPort)])
  const pbase = `http://localhost:${pubPort}`
  const pup = await waitUp(pbase + '/')
  test('公网服务启动', pup)
  if (pup) {
    const phome = await (await fetch(pbase + '/')).text()
    test('公网首页不含本地路径栏（只 URL）', !phome.includes('pathbar') && phome.includes('公开仓库地址'))
    // 公网模式禁止目录浏览（防止扫服务器硬盘）
    const browseBlocked = await fetch(pbase + '/browse?dir=/etc')
    test('公网模式拒绝目录浏览 (403)', browseBlocked.status === 403, `status=${browseBlocked.status}`)
    // 公网模式禁止本地路径扫描
    const blocked = await fetch(pbase + '/scan?path=/etc')
    test('公网模式拒绝本地路径扫描 (403)', blocked.status === 403, `status=${blocked.status}`)
    // 公网模式拒绝上传
    const noupload = await fetch(pbase + '/scan-files', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"files":[]}' })
    test('公网模式拒绝上传 (403)', noupload.status === 403, `status=${noupload.status}`)
  }
  try { pubSrv.kill() } catch {}

  console.log(`\n========== Web 测试: ${passed} 通过, ${failed} 失败 ==========\n`)
  if (failed > 0) process.exit(1)
}

main().catch(e => { console.error('测试崩溃:', e); process.exit(1) })
