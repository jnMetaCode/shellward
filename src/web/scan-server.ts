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
import { mkdtempSync, rmSync, existsSync, statSync, mkdirSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join, resolve, dirname, normalize, isAbsolute } from 'path'
import { runProjectComplianceAudit } from '../compliance/audit.js'
import { renderHtmlReport } from '../compliance/html-report.js'
import { DEFAULT_CONFIG, resolveLocale } from '../types.js'

const REPO_RE = /^https:\/\/(github\.com|gitlab\.com|gitee\.com|bitbucket\.org)\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?(?:\.git)?\/?$/
const CLONE_TIMEOUT_MS = 60_000
const MAX_CONCURRENT = 4

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
      // 本地客户端：选文件夹上传（仅本地模式；数据只到 localhost、不出本机）
      if (u.pathname === '/scan-files' && req.method === 'POST') {
        if (!opts.local) return send(res, 403, 'text/html', errorPage('公网模式不支持上传；请用「公开仓库 URL」。'))
        if (active >= MAX_CONCURRENT) return send(res, 503, 'text/html', errorPage('服务繁忙，请稍后再试'))
        return await handleUpload(req, res, locale, () => { active++ }, () => { active-- })
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
    const msg = esc(e?.message || String(e))
    send(res, 502, 'text/html', errorPage(
      `克隆/扫描失败：${msg}。<br><br>可能原因：仓库过大（克隆超时 60s）、私有仓库、或地址有误。<br>` +
      `<b>大仓库 / 私有代码请用本地客户端</b>（选文件夹、不上传）：<code>npx shellward web --local</code>，或命令行 <code>npx shellward scan</code>。`))
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

const MAX_UPLOAD_BYTES = 16 * 1024 * 1024 // 16MB JSON 上限

/** 本地上传：客户端把选中的文件夹读成 {path,content}[] 发来，写入临时目录后扫描 */
async function handleUpload(req: any, res: any, locale: 'zh' | 'en', inc: () => void, dec: () => void) {
  let body = ''
  let size = 0
  let aborted = false
  await new Promise<void>((resolveBody) => {
    req.on('data', (c: Buffer) => {
      size += c.length
      if (size > MAX_UPLOAD_BYTES) { aborted = true; req.destroy(); resolveBody(); return }
      body += c.toString('utf8')
    })
    req.on('end', () => resolveBody())
    req.on('error', () => { aborted = true; resolveBody() })
  })
  if (aborted) return send(res, 413, 'text/html', errorPage('内容过大或读取失败（上限 16MB）。大项目请用本地 CLI：npx shellward scan'))

  let payload: { root?: string; files?: { path: string; content: string }[] }
  try { payload = JSON.parse(body) } catch { return send(res, 400, 'text/html', errorPage('上传数据格式错误')) }
  const files = Array.isArray(payload.files) ? payload.files : []
  if (files.length === 0) return send(res, 400, 'text/html', errorPage('未选择任何文件'))

  const dir = mkdtempSync(join(tmpdir(), 'sw-up-'))
  inc()
  try {
    for (const f of files) {
      if (!f || typeof f.path !== 'string' || typeof f.content !== 'string') continue
      // 路径安全：去掉绝对路径/.. 逃逸，落在临时目录内
      const rel = normalize(f.path).replace(/^(\.\.(\/|\\|$))+/, '')
      if (isAbsolute(rel) || rel.includes('..')) continue
      const dest = join(dir, rel)
      if (!dest.startsWith(dir)) continue
      try { mkdirSync(dirname(dest), { recursive: true }); writeFileSync(dest, f.content) } catch { /* skip */ }
    }
    const { report, scan } = runProjectComplianceAudit(DEFAULT_CONFIG, dir)
    const rootName = typeof payload.root === 'string' && payload.root ? payload.root : '(uploaded folder)'
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root: rootName }))
  } catch (e: any) {
    send(res, 500, 'text/html', errorPage('扫描失败：' + esc(e?.message || String(e))))
  } finally {
    dec()
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
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
  const urlForm = `
      <form action="/scan" method="get" onsubmit="var b=this.querySelector('button');b.disabled=true;b.textContent='扫描中…（大仓库需 10–60 秒，请勿重复点击）';">
        <label>${local ? '② ' : ''}公开仓库地址</label>
        <input name="repo" placeholder="https://github.com/owner/repo"${local ? '' : ' autofocus'}>
        <button type="submit">${local ? '体检该仓库 →' : '开始体检 →'}</button>
        <p class="hint">仅支持公开仓库（GitHub / GitLab / Gitee / Bitbucket）。大仓库可能超时——${local ? '此时改用上方「选择文件夹」更稳。' : '<b>大仓库 / 私有代码请用本地客户端或 CLI</b>：<code>npx shellward web --local</code> / <code>npx shellward scan</code>（不上传）。'}</p>
      </form>`

  const uploadForm = local ? `
      <form id="dirform">
        <label>① 选择本地项目文件夹（推荐）</label>
        <input type="file" id="dir" webkitdirectory directory multiple>
        <button id="dbtn" type="submit">开始体检 →</button>
        <div id="status" class="status"></div>
        <p class="hint">📂 直接选你的项目文件夹，无需敲路径。文件仅发送到<b>本机的本地服务</b>处理，<b>不经过任何外部服务器、不出本机</b>。</p>
      </form>
      <div class="or">— 或 —</div>` : ''

  return page('ShellWard 合规体检', `
    <div class="hero">
      <div class="logo">🛡️ Shell<span>Ward</span> 合规网关</div>
      <h1>AI 应用合规体检</h1>
      <p class="sub">${local ? '选项目文件夹或贴公开仓库链接' : '贴公开仓库链接'}，30 秒查出数据出境 / 硬编码密钥 / 个人信息暴露等中国合规红线。</p>
      ${uploadForm}
      ${urlForm}
      <p class="foot">网安法 2026 · PIPL · 等保2.0 · 数据出境 · AI标识 ｜ 零依赖 · 开源 ·
        <a href="https://github.com/jnMetaCode/shellward">GitHub ⭐</a></p>
    </div>
    ${local ? UPLOAD_SCRIPT : ''}`)
}

// 客户端：读取所选文件夹 → 过滤(跳过 node_modules 等、仅文本/配置、限大小) → POST 到本机服务
// 注意：过滤后缀须与服务端 SCAN_EXT 对齐（含 .md），否则 markdown 项目会被全滤光显得"扫不了"。
const UPLOAD_SCRIPT = `<script>
(function(){
  var SKIP=/(^|\\/)(node_modules|\\.git|dist|build|\\.next|out|vendor|coverage|\\.venv|venv|__pycache__|target|\\.cache)(\\/|$)/;
  var EXT=/\\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|java|php|rs|json|yaml|yml|toml|ini|conf|sh|txt|csv|md|mdx|ipynb|properties|xml|gradle|tf)$/i;
  var ENV=/(^|\\/)\\.env(\\.|$)/; var DEP=/^(package\\.json|requirements\\.txt|pyproject\\.toml|go\\.mod)$/;
  var form=document.getElementById('dirform'); if(!form) return;
  var statusEl=document.getElementById('status');
  function s(m){ if(statusEl){statusEl.textContent=m;statusEl.style.display='block';} }
  form.addEventListener('submit', async function(e){
    e.preventDefault();
    var inp=document.getElementById('dir'), btn=document.getElementById('dbtn');
    if(!inp.files||!inp.files.length){ s('请先点上方按钮选择项目文件夹'); return; }
    btn.disabled=true;
    var picked=[], total=0, root='';
    for(var i=0;i<inp.files.length;i++){
      var f=inp.files[i], rel=f.webkitRelativePath||f.name; if(!root)root=rel.split('/')[0];
      if(SKIP.test(rel)) continue;
      var base=rel.split('/').pop();
      if(!(EXT.test(rel)||ENV.test(rel)||DEP.test(base))) continue;
      if(f.size>524288) continue;
      if(picked.length>=3000||total>8388608) break;
      total+=f.size; picked.push(f);
    }
    if(!picked.length){ s('未找到可扫描的源码/配置文件（已自动跳过 node_modules、图片、超大文件）。请选含代码或配置的目录。'); btn.disabled=false; return; }
    s('读取 '+picked.length+' 个文件…');
    var out=[]; for(var j=0;j<picked.length;j++){ try{ out.push({path:picked[j].webkitRelativePath||picked[j].name, content:await picked[j].text()}); }catch(_){} }
    s('扫描中…（'+out.length+' 个文件，请稍候）');
    try{
      var resp=await fetch('/scan-files',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({root:root,files:out})});
      if(!resp.ok){ s('扫描失败：HTTP '+resp.status+'。请重试，或改用命令行 npx shellward scan。'); btn.disabled=false; return; }
      var html=await resp.text();
      // 用 Blob URL 跳转展示报告（比 document.write 可靠）
      window.location.href=URL.createObjectURL(new Blob([html],{type:'text/html'}));
    }catch(err){ s('扫描失败：'+(err&&err.message||err)+'。请重试。'); btn.disabled=false; }
  });
})();
</script>`

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
input[type=file]{padding:12px;background:#f8fafc;cursor:pointer}
button{background:#cb0000;color:#fff;border:0;border-radius:10px;padding:14px;font-size:16px;
font-weight:700;cursor:pointer;margin-top:4px}button:hover{background:#a80000}
button:disabled{background:#94a3b8;cursor:default}
form{margin:0 0 14px}.or{text-align:center;color:#94a3b8;font-size:13px;margin:6px 0 14px}
.status{display:none;margin:10px 0 0;padding:10px 14px;border-radius:8px;background:#f1f5f9;
color:#334155;font-size:13.5px;border-left:3px solid #cb0000;text-align:left}
.foot{margin:24px 0 0;font-size:12.5px;color:#94a3b8}.foot a,.back{color:#cb0000;text-decoration:none}
.back{font-weight:600}
</style></head><body>${body}</body></html>`
}

function esc(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}
