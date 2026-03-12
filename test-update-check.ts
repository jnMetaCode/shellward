#!/usr/bin/env npx tsx
// test-update-check.ts — Test version check, notification dedup, remote vuln DB, caching

import { checkForUpdate, fetchVulnDB, compareVersions } from './src/update-check'
import { unlinkSync } from 'fs'
import { join } from 'path'

const CACHE_DIR = join(process.env.HOME || '~', '.openclaw', 'shellward')

let pass = 0, fail = 0
function test(name: string, ok: boolean, detail?: string) {
  ok ? pass++ : fail++
  console.log(ok ? `  \u2705 ${name}` : `  \u274C ${name}${detail ? ' \u2014 ' + detail : ''}`)
}

// Clean caches for fresh test
try { unlinkSync(join(CACHE_DIR, 'update-cache.json')) } catch {}
try { unlinkSync(join(CACHE_DIR, 'vuln-db-cache.json')) } catch {}

// === 1. compareVersions ===
console.log('\n=== compareVersions ===')
test('0.4.0 > 0.3.4', compareVersions('0.4.0', '0.3.4') > 0)
test('0.3.4 < 0.4.0', compareVersions('0.3.4', '0.4.0') < 0)
test('0.4.0 == 0.4.0', compareVersions('0.4.0', '0.4.0') === 0)
test('1.0.0 > 0.9.9', compareVersions('1.0.0', '0.9.9') > 0)
test('2026.3.8 > 2026.3.6', compareVersions('2026.3.8', '2026.3.6') > 0)
test('2026.3.2 < 2026.3.4', compareVersions('2026.3.2', '2026.3.4') < 0)

// === 2. npm 版本检查 ===
console.log('\n=== npm 版本检查 ===')
const t1 = Date.now()
const r1 = await checkForUpdate('0.0.1')
const e1 = Date.now() - t1

if (r1) {
  test('返回结果', true)
  test('版本号格式正确', /^\d+\.\d+\.\d+/.test(r1.latest))
  test('检测到有更新', r1.updateAvailable === true)
  test('首次应该通知', r1.shouldNotify === true)
  test(`响应时间 (${e1}ms)`, e1 < 10000)
  console.log(`  \u2139\uFE0F npm latest: ${r1.latest}`)
} else {
  test('网络不可用时返回 null', r1 === null)
  console.log('  \u26A0\uFE0F 跳过网络测试')
}

// === 3. 重复通知测试（核心！）===
console.log('\n=== 重复通知测试 ===')
const r2 = await checkForUpdate('0.0.1')
if (r2) {
  test('第二次不应该通知 (shouldNotify=false)', r2.shouldNotify === false)
  test('但仍然返回 updateAvailable=true', r2.updateAvailable === true)

  // 第三次也不通知
  const r3 = await checkForUpdate('0.0.1')
  test('第三次也不通知', r3?.shouldNotify === false)
} else {
  test('网络不可用，跳过', true)
}

// 超高版本号 — 不需要更新
const r4 = await checkForUpdate('99.99.99')
if (r4) {
  test('最新版不提示更新', r4.updateAvailable === false)
  test('最新版不通知', r4.shouldNotify === false)
}

// === 4. 缓存性能 ===
console.log('\n=== 缓存性能 ===')
const t2 = Date.now()
await checkForUpdate('0.0.1')
const e2 = Date.now() - t2
test(`缓存命中 (${e2}ms < 10ms)`, e2 < 10)

// === 5. 远程漏洞数据库 ===
console.log('\n=== 远程漏洞数据库 ===')
const t3 = Date.now()
const { vulns, alerts } = await fetchVulnDB()
const e3 = Date.now() - t3

if (vulns.length > 0) {
  test('漏洞数据返回', true)
  test(`${vulns.length} 条漏洞`, vulns.length >= 1)
  test('结构完整 (id)', typeof vulns[0].id === 'string')
  test('结构完整 (severity)', ['CRITICAL', 'HIGH', 'MEDIUM'].includes(vulns[0].severity))
  test('结构完整 (中文)', vulns[0].description_zh.length > 0)
  test('结构完整 (英文)', vulns[0].description_en.length > 0)
  test('供应链警告结构', Array.isArray(alerts))
  console.log(`  \u2139\uFE0F ${vulns.length} 漏洞, ${alerts.length} 供应链警告, ${e3}ms`)

  // 版本匹配
  const old = vulns.filter(v => compareVersions('1.0.50', v.affectedBelow) < 0)
  test('旧版本检出漏洞', old.length > 0)
  const fresh = vulns.filter(v => compareVersions('2026.99.99', v.affectedBelow) < 0)
  test('新版本无漏洞', fresh.length === 0)
} else {
  console.log('  \u26A0\uFE0F 远程不可用 (vuln-db.json 未推送)')
  test('降级为空数组', Array.isArray(vulns))
}

// === 6. 漏洞库缓存 ===
console.log('\n=== 漏洞库缓存 ===')
const t4 = Date.now()
await fetchVulnDB()
const e4 = Date.now() - t4
test(`缓存命中 (${e4}ms < 10ms)`, e4 < 10)

// === 7. 模拟"新版本发布"场景 ===
console.log('\n=== 新版本发布场景 ===')
// 清除缓存模拟全新状态
try { unlinkSync(join(CACHE_DIR, 'update-cache.json')) } catch {}
const fresh1 = await checkForUpdate('0.0.1')
test('全新用户首次收到通知', fresh1?.shouldNotify === true)
const fresh2 = await checkForUpdate('0.0.1')
test('同一会话第二次不通知', fresh2?.shouldNotify === false)

// === Summary ===
console.log('\n========================================')
console.log(`  更新检查测试: ${pass} 通过, ${fail} 失败 (共 ${pass + fail} 项)`)
console.log(fail === 0 ? '  全部通过!' : '  有失败项。')
console.log('========================================\n')
process.exit(fail > 0 ? 1 : 0)
