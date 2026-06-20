#!/usr/bin/env npx tsx
// bench/scan-bench.ts — 合规扫描检测基准
//
// 用标注语料跑「真实 scanProject 管线」，算精确率/召回率/F1，把"信我能检"变成"看数字"。
// 正例=应检出的真实风险；硬负例=不该误报的（境内端点/占位符/文档示例/lock/无效校验位）。
//   npx tsx bench/scan-bench.ts          打印结果
//   npx tsx bench/scan-bench.ts --ci     精确率或召回率低于阈值则非零退出（CI 门禁）

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { scanProject } from '../src/compliance/project-scan'
import type { FindingKind } from '../src/compliance/project-scan'

type Expect = FindingKind | 'none'
interface Case { id: string; path: string; content: string; expect: Expect; note: string }

const C: Case[] = [
  // ===== 正例：境外端点 / SDK 依赖 =====
  { id: 'p01', path: 'a.ts', content: 'const u="https://api.openai.com/v1"', expect: 'overseas', note: 'OpenAI 端点(代码)' },
  { id: 'p02', path: 'b.py', content: 'BASE="https://api.anthropic.com"', expect: 'overseas', note: 'Anthropic 端点' },
  { id: 'p03', path: 'c.js', content: 'const g="https://generativelanguage.googleapis.com/v1"', expect: 'overseas', note: 'Gemini 端点' },
  { id: 'p04', path: 'package.json', content: '{"dependencies":{"openai":"^4"}}', expect: 'overseas', note: 'openai 依赖' },
  { id: 'p05', path: 'requirements.txt', content: 'flask==2.0\nanthropic>=0.20', expect: 'overseas', note: 'anthropic 依赖(py)' },
  { id: 'p06', path: 'go.mod', content: 'module x\nrequire github.com/sashabaranov/go-openai v1.2.0', expect: 'overseas', note: 'go-openai 依赖' },
  // ===== 正例：密钥 =====
  { id: 'p07', path: 'k1.js', content: 'const k="sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq"', expect: 'secret', note: 'OpenAI key' },
  { id: 'p08', path: 'k2.ts', content: 'const t="ghp_Rz9MkP2qWlS7yV3nD8tB1hC4xJ6pQsTuVwYz"', expect: 'secret', note: 'GitHub token(36位)' },
  { id: 'p09', path: 'k3.py', content: 'AWS="AKIARZ9MKP2QWLS7YV3N"', expect: 'secret', note: 'AWS key(真实格式)' },
  { id: 'p10', path: 'k4.txt', content: '-----BEGIN RSA PRIVATE KEY-----', expect: 'secret', note: '私钥' },
  { id: 'p11', path: 'k5.env', content: 'DB_PASSWORD=Sup3rS3cretPwd2026', expect: 'secret', note: '口令' },
  // ===== 正例：中文 PII =====
  { id: 'p12', path: 'd1.txt', content: '身份证 110101199003071233', expect: 'pii', note: '身份证(校验位有效)' },
  { id: 'p13', path: 'd2.ts', content: 'const phone="13912345678"', expect: 'pii', note: '手机号' },
  { id: 'p14', path: 'd3.json', content: '{"card":"4111111111111111"}', expect: 'pii', note: '银行卡(Luhn)' },
  { id: 'p15', path: 'd4.txt', content: 'SSN: 123-45-6789', expect: 'pii', note: 'US SSN' },

  // ===== 硬负例：不该误报 =====
  { id: 'n01', path: 'dom1.ts', content: 'const u="https://dashscope.aliyuncs.com/compatible-mode/v1"', expect: 'none', note: '境内通义端点' },
  { id: 'n02', path: 'dom2.ts', content: 'const u="https://api.deepseek.com"', expect: 'none', note: '境内 DeepSeek 端点' },
  { id: 'n03', path: 'ph1.ts', content: 'const k="sk-EXAMPLEEXAMPLEEXAMPLE12"', expect: 'none', note: '占位符 key(EXAMPLE)' },
  { id: 'n04', path: 'ph2.ts', content: 'API_KEY=your-api-key-placeholder-here', expect: 'none', note: '占位符 your-...' },
  { id: 'n05', path: 'README.md', content: '示例: key=sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq 手机 13912345678', expect: 'none', note: 'Markdown 文档示例' },
  { id: 'n06', path: 'package-lock.json', content: '{"x":"sk-RZ9mKp2QwLs7Yv3Nd8Tb1Hc4Xj6Pq"}', expect: 'none', note: 'lock 文件(噪声)' },
  { id: 'n07', path: 'badid.txt', content: '身份证 110101199003071234', expect: 'none', note: '身份证校验位错误' },
  { id: 'n08', path: 'badphone.txt', content: '工号 12345678901', expect: 'none', note: '非手机号' },
  { id: 'n09', path: 'b64.ts', content: 'const h="YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc="', expect: 'none', note: '普通 base64(非密钥)' },
  { id: 'n10', path: 'pkg2/package.json', content: '{"dependencies":{"express":"^4","lodash":"^4"}}', expect: 'none', note: '纯境内无关依赖' },
  // ===== 追加：更难的样例 =====
  { id: 'p16', path: 'e.ts', content: 'const c="https://api.cohere.ai/v1/chat"', expect: 'overseas', note: 'Cohere 端点' },
  { id: 'p17', path: 'GUIDE.md', content: '调用示例：向 https://api.openai.com/v1 发请求', expect: 'overseas', note: 'Markdown 里的境外端点(应保留检测)' },
  { id: 'p18', path: 'r2.txt', content: 'dep: @langchain/openai and langchain-anthropic', expect: 'none', note: '散文提到包名(非依赖清单,不应误报)' },
  { id: 'n11', path: 'sha.ts', content: 'const commit="a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"', expect: 'none', note: 'git commit sha(40hex,非密钥)' },
  { id: 'n12', path: 'req2/requirements.txt', content: 'dashscope==1.0\nzhipuai>=2.0', expect: 'none', note: '境内 SDK 依赖(不算出境)' },
  { id: 'n13', path: 'uuid.ts', content: 'const id="550e8400-e29b-41d4-a716-446655440000"', expect: 'none', note: 'UUID(非密钥/PII)' },
]

function run(ci: boolean) {
  const dir = mkdtempSync(join(tmpdir(), 'sw-bench-'))
  try {
    for (const c of C) {
      const full = join(dir, c.id, c.path)
      mkdirSync(join(full, '..'), { recursive: true })
      writeFileSync(full, c.content)
    }
    const scan = scanProject(dir)
    const byCase = (id: string) => scan.findings.filter(f => f.file.startsWith(id + '/'))

    let tp = 0, fp = 0, fn = 0, tn = 0
    const fails: string[] = []
    console.log('\n========== ShellWard 扫描检测基准 ==========\n')
    for (const c of C) {
      const found = byCase(c.id)
      const hit = c.expect === 'none' ? found.length === 0 : found.some(f => f.kind === c.expect)
      if (c.expect === 'none') {
        if (found.length === 0) { tn++ } else { fp++; fails.push(`FP  ${c.id} ${c.note} — 误报: ${found.map(f => f.kind).join(',')}`) }
      } else {
        if (hit) { tp++ } else { fn++; fails.push(`FN  ${c.id} ${c.note} — 漏报 (期望 ${c.expect})`) }
      }
      console.log(`  ${hit ? '✅' : '❌'} [${c.expect === 'none' ? '负' : '正'}] ${c.id} ${c.note}`)
    }

    const precision = tp + fp === 0 ? 1 : tp / (tp + fp)
    const recall = tp + fn === 0 ? 1 : tp / (tp + fn)
    const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall)
    console.log('\n--- 指标 ---')
    console.log(`  正例 ${tp + fn} ｜ 负例 ${tn + fp}`)
    console.log(`  TP=${tp} FP=${fp} FN=${fn} TN=${tn}`)
    console.log(`  精确率 Precision: ${(precision * 100).toFixed(1)}%`)
    console.log(`  召回率 Recall:    ${(recall * 100).toFixed(1)}%`)
    console.log(`  F1:               ${(f1 * 100).toFixed(1)}%`)
    if (fails.length) { console.log('\n--- 未通过 ---'); fails.forEach(f => console.log('  ' + f)) }
    console.log('')

    if (ci) {
      const PASS = precision >= 0.9 && recall >= 0.9
      console.log(PASS ? '✅ 基准达标 (P≥90% R≥90%)' : '❌ 基准未达标')
      if (!PASS) process.exit(1)
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

run(process.argv.includes('--ci'))
