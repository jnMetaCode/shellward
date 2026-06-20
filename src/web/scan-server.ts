// src/web/scan-server.ts — ShellWard 合规扫描 web 服务（零依赖）
//
// 双模式，一份代码两用：
//   1) 公网模式（部署）：贴「公开仓库 URL」或访问 /scan?repo=URL → 浅克隆 + 扫描 + 出报告
//      公开仓库的代码本就公开，服务端扫描不涉及数据出境；私有代码引导用本地 CLI。
//   2) 本地模式（shellward web --local，仅 127.0.0.1）：填「本地路径」扫描，私有代码不上传
//      —— 这就是「客户端」体验（浏览器 GUI、不用命令行），但零 Electron 包袱。
//
// 安全加固：
//   - 仓库 URL 域名白名单（github/gitlab/gitee...），严格正则，拒带凭据的 URL
//   - 浅克隆 --depth 1 --single-branch，GIT_TERMINAL_PROMPT=0（不卡在私有库鉴权），30s 超时
//   - 临时目录隔离，用完即删；扫描器只读文件、绝不执行仓库代码
//   - 本地路径扫描仅在 --local 模式开放（公网模式拒绝 path 参数，防止扫服务器硬盘）
//   - 并发上限，防滥用

import { createServer } from 'http'
import { spawn } from 'child_process'
import { mkdtempSync, rmSync, existsSync, statSync } from 'fs'
import { tmpdir } from 'os'
import { join, resolve } from 'path'
import { runProjectComplianceAudit } from '../compliance/audit.js'
import { renderHtmlReport } from '../compliance/html-report.js'
import { DEFAULT_CONFIG, resolveLocale } from '../types.js'

const REPO_RE = /^https:\/\/(github\.com|gitlab\.com|gitee\.com|bitbucket\.org)\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?(?:\.git)?\/?$/
const CLONE_TIMEOUT_MS = 30_000
const MAX_CONCURRENT = 2

export interface WebServerOptions {
  port: number
  /** 本地模式：开放本地路径扫描、仅监听 127.0.0.1 */
  local?: boolean
}

/** 校验仓库 URL：仅允许白名单代码托管域名，拒绝带凭据/异常字符 */
export function validateRepoUrl(input: string): { ok: true; url: string } | { ok: false; reason: string } {
  const url = (input || '').trim()
  if (!url) return { ok: false, reason: '请输入仓库地址' }
  if (url.includes('@') || /\s/.test(url)) return { ok: false, reason: '地址含非法字符' }
  if (!REPO_RE.test(url)) return { ok: false, reason: '仅支持 github.com / gitlab.com / gitee.com / bitbucket.org 的公开仓库 URL' }
  return { ok: true, url }
}

export function startWebServer(opts: WebServerOptions): void {
  const locale = resolveLocale(DEFAULT_CONFIG)
  const host = opts.local ? '127.0.0.1' : '0.0.0.0'
  let active = 0

  const server = createServer(async (req, res) => {
    try {
      const u = new URL(req.url || '/', `http://localhost:${opts.port}`)
      if (u.pathname === '/' || u.pathname === '') {
        return send(res, 200, 'text/html', formPage(!!opts.local))
      }
      if (u.pathname === '/scan') {
        if (active >= MAX_CONCURRENT) {
          return send(res, 503, 'text/html', errorPage('服务繁忙，请稍后再试（并发上限）'))
        }
        const repo = u.searchParams.get('repo')
        const path = u.searchParams.get('path')

        // 本地路径扫描：仅本地模式开放
        if (path) {
          if (!opts.local) return send(res, 403, 'text/html', errorPage('公网模式不支持本地路径扫描；请用「公开仓库 URL」，私有代码请用本地 CLI：npx shellward scan'))
          return await handleLocal(res, path, locale, () => { active++ }, () => { active-- })
        }
        if (repo) {
          return await handleRepo(res, repo, locale, () => { active++ }, () => { active-- })
        }
        return send(res, 400, 'text/html', errorPage('缺少参数：repo（仓库 URL）' + (opts.local ? ' 或 path（本地路径）' : '')))
      }
      send(res, 404, 'text/html', errorPage('页面不存在'))
    } catch (e: any) {
      send(res, 500, 'text/html', errorPage('内部错误：' + esc(e?.message || String(e))))
    }
  })

  server.on('error', (e: any) => {
    console.error(`[ShellWard web] 启动失败: ${e?.message}`)
    process.exit(1)
  })
  server.listen(opts.port, host, () => {
    const url = `http://localhost:${opts.port}`
    if (opts.local) {
      console.log(`🌐 ShellWard 本地合规扫描（客户端模式）: ${url}\n   填本地路径即可扫描，私有代码不上传、不出本机。Ctrl+C 退出。`)
    } else {
      console.log(`🌐 ShellWard 公开仓库合规扫描: ${url} (监听 ${host}:${opts.port})\n   贴公开仓库 URL 即可体检。私有代码请用本地 CLI: npx shellward scan`)
    }
  })
}

async function handleRepo(res: any, repo: string, locale: 'zh' | 'en', inc: () => void, dec: () => void) {
  const v = validateRepoUrl(repo)
  if (!v.ok) return send(res, 400, 'text/html', errorPage(v.reason))
  const dir = mkdtempSync(join(tmpdir(), 'sw-web-'))
  inc()
  try {
    await cloneRepo(v.url, dir)
    const { report, scan } = runProjectComplianceAudit(DEFAULT_CONFIG, dir)
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root: v.url }))
  } catch (e: any) {
    send(res, 502, 'text/html', errorPage('克隆/扫描失败：' + esc(e?.message || String(e)) + '。请确认是可公开访问的仓库。'))
  } finally {
    dec()
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
}

async function handleLocal(res: any, path: string, locale: 'zh' | 'en', inc: () => void, dec: () => void) {
  const root = resolve(path)
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    return send(res, 400, 'text/html', errorPage('路径不存在或不是目录：' + esc(root)))
  }
  inc()
  try {
    const { report, scan } = runProjectComplianceAudit(DEFAULT_CONFIG, root)
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root }))
  } finally {
    dec()
  }
}

/** 浅克隆公开仓库到临时目录（不鉴权、超时、不执行任何仓库代码） */
function cloneRepo(url: string, dir: string): Promise<void> {
  return new Promise((res, rej) => {
    const p = spawn('git', ['clone', '--depth', '1', '--single-branch', '--no-tags', url, dir], {
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'true' },
      timeout: CLONE_TIMEOUT_MS,
      stdio: 'ignore',
    })
    p.on('error', rej)
    p.on('close', (code, signal) => {
      if (signal) return rej(new Error('克隆超时'))
      code === 0 ? res() : rej(new Error('克隆失败 (git exit ' + code + ')'))
    })
  })
}

// ===== 页面 =====

function send(res: any, code: number, type: string, body: string) {
  res.writeHead(code, { 'Content-Type': type + '; charset=utf-8', 'X-Content-Type-Options': 'nosniff' })
  res.end(body)
}

function formPage(local: boolean): string {
  const field = local
    ? `<label>本地项目路径</label>
       <input name="path" placeholder="/Users/you/your-ai-project" autofocus>
       <p class="hint">本地模式：代码不上传、不出本机（客户端体验）。</p>`
    : `<label>公开仓库地址</label>
       <input name="repo" placeholder="https://github.com/owner/repo" autofocus>
       <p class="hint">仅支持公开仓库（GitHub / GitLab / Gitee / Bitbucket）。<b>私有/敏感代码请用本地 CLI</b>：<code>npx shellward scan</code>（不上传）。</p>`
  return page('ShellWard 合规体检', `
    <div class="hero">
      <div class="logo">🛡️ Shell<span>Ward</span> 合规网关</div>
      <h1>AI 应用合规体检</h1>
      <p class="sub">${local ? '填本地路径' : '贴公开仓库链接'}，30 秒查出数据出境 / 硬编码密钥 / 个人信息暴露等中国合规红线。</p>
      <form action="/scan" method="get">
        ${field}
        <button type="submit">开始体检 →</button>
      </form>
      <p class="foot">网安法 2026 · PIPL · 等保2.0 · 数据出境 · AI标识 ｜ 零依赖 · 开源 ·
        <a href="https://github.com/jnMetaCode/shellward">GitHub ⭐</a></p>
    </div>`)
}

function errorPage(msg: string): string {
  return page('出错了', `<div class="hero"><div class="logo">🛡️ Shell<span>Ward</span></div>
    <h1>⚠️ 无法完成</h1><p class="sub">${esc(msg)}</p>
    <p><a class="back" href="/">← 返回重试</a></p></div>`)
}

function page(title: string, body: string): string {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;
background:linear-gradient(135deg,#eef1f6,#e2e8f0);color:#0f172a;
font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.hero{background:#fff;max-width:560px;width:92%;margin:40px;padding:40px;border-radius:18px;
box-shadow:0 12px 40px rgba(15,23,42,.12);text-align:center}
.logo{font-weight:800;font-size:15px}.logo span{color:#cb0000}
h1{font-size:30px;margin:14px 0 8px;letter-spacing:-.5px}
.sub{color:#64748b;margin:0 0 26px}
form{display:flex;flex-direction:column;gap:10px;text-align:left}
label{font-size:13px;font-weight:600;color:#475569}
input{padding:14px 16px;border:1px solid #cbd5e1;border-radius:10px;font-size:16px;width:100%}
input:focus{outline:none;border-color:#cb0000;box-shadow:0 0 0 3px rgba(203,0,0,.12)}
.hint{font-size:12.5px;color:#64748b;margin:2px 0 6px}
.hint code{background:#f1f5f9;padding:1px 6px;border-radius:5px}
button{background:#cb0000;color:#fff;border:0;border-radius:10px;padding:14px;font-size:16px;
font-weight:700;cursor:pointer;margin-top:4px}button:hover{background:#a80000}
.foot{margin:24px 0 0;font-size:12.5px;color:#94a3b8}.foot a,.back{color:#cb0000;text-decoration:none}
.back{font-weight:600}
</style></head><body>${body}</body></html>`
}

function esc(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}
