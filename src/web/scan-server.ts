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
import { mkdtempSync, rmSync, existsSync, statSync, mkdirSync, writeFileSync, readdirSync } from 'fs'
import { tmpdir, homedir } from 'os'
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

// 报告「返回」链接：本地模式用绝对地址（上传报告经 blob: URL 打开，相对 '/' 会失效）
let SERVER_BASE = '/'

export function startWebServer(opts: WebServerOptions): void {
  const locale = resolveLocale(DEFAULT_CONFIG)
  const host = opts.local ? '127.0.0.1' : '0.0.0.0'
  SERVER_BASE = opts.local ? `http://localhost:${opts.port}/` : '/'
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
      // 本地目录浏览（仅本地模式）：服务端直接列子目录，让用户点选要扫的文件夹（零上传）
      if (u.pathname === '/browse') {
        if (!opts.local) return send(res, 403, 'application/json', JSON.stringify({ error: '仅本地模式可用' }))
        return handleBrowse(res, u.searchParams.get('dir'))
      }
      // 演示：扫一个内置的「含风险样例项目」——证明"秒出≠没检查"（满屏发现 + 行号）
      if (u.pathname === '/demo') {
        if (active >= MAX_CONCURRENT) return send(res, 503, 'text/html', errorPage('服务繁忙，请稍后再试'))
        return handleDemo(res, locale, () => { active++ }, () => { active-- })
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
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root: v.url, backLink: SERVER_BASE }))
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
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root, backLink: SERVER_BASE }))
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
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root: rootName, backLink: SERVER_BASE }))
  } catch (e: any) {
    send(res, 500, 'text/html', errorPage('扫描失败：' + esc(e?.message || String(e))))
  } finally {
    dec()
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
}

/** 本地目录浏览：返回某目录下的子目录列表（供网页点选；不读文件内容、不上传） */
function handleBrowse(res: any, dirParam: string | null) {
  try {
    const abs = resolve(dirParam && dirParam.trim() ? dirParam : homedir())
    const entries = readdirSync(abs, { withFileTypes: true })
      .filter(e => { try { return e.isDirectory() } catch { return false } })
      .map(e => e.name)
      .filter(n => !n.startsWith('.') && n !== 'node_modules')
      .sort((a, b) => a.localeCompare(b))
      .slice(0, 500)
    const parent = dirname(abs)
    send(res, 200, 'application/json', JSON.stringify({
      current: abs,
      parent: parent === abs ? null : parent,
      dirs: entries,
    }))
  } catch (e: any) {
    send(res, 200, 'application/json', JSON.stringify({ error: e?.message || String(e) }))
  }
}

/** 演示：内置「含风险样例项目」扫描，证明检测真在工作 */
function handleDemo(res: any, locale: 'zh' | 'en', inc: () => void, dec: () => void) {
  const dir = mkdtempSync(join(tmpdir(), 'sw-demo-'))
  inc()
  try {
    mkdirSync(join(dir, 'src'), { recursive: true })
    mkdirSync(join(dir, 'data'), { recursive: true })
    writeFileSync(join(dir, 'package.json'), JSON.stringify({
      name: 'demo-ai-app', dependencies: { 'openai': '^4.20.0', '@anthropic-ai/sdk': '^0.20.0', 'express': '^4' },
    }, null, 2))
    writeFileSync(join(dir, 'src', 'config.ts'),
      'export const LLM = "https://api.openai.com/v1"\n'
      + 'const OPENAI_KEY = "sk-Rz9MkP2qWlS7yV3nD8tB1hC4xJ6pQsTuVwYz0"\n'
      + 'const GITHUB_TOKEN = "ghp_Rz9MkP2qWlS7yV3nD8tB1hC4xJ6pQsTuVwYz"\n'
      + 'export const ADMIN_PHONE = "13912345678"\n')
    writeFileSync(join(dir, 'data', 'customers.csv'),
      'name,id_card,phone,card\n张三,110101199003071233,13800138000,4111111111111111\n')
    writeFileSync(join(dir, '.env'),
      'AWS_ACCESS_KEY=AKIARZ9MKP2QWLS7YV3N\nDB_PASSWORD=Sup3rS3cretProdPwd2026\n')
    const { report, scan } = runProjectComplianceAudit(DEFAULT_CONFIG, dir)
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root: '示例项目（含风险）/ demo-ai-app', backLink: SERVER_BASE }))
  } catch (e: any) {
    send(res, 500, 'text/html', errorPage('演示失败：' + esc(e?.message || String(e))))
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
        <label>公开仓库地址</label>
        <input name="repo" placeholder="https://github.com/owner/repo"${local ? '' : ' autofocus'}>
        <button type="submit">${local ? '体检该仓库 →' : '开始体检 →'}</button>
        <p class="hint">仅支持公开仓库（GitHub / GitLab / Gitee / Bitbucket）。大仓库可能超时——${local ? '此时用上方「上传文件夹」更稳。' : '<b>大仓库 / 私有代码请用本地客户端或 CLI</b>：<code>npx shellward web --local</code> / <code>npx shellward scan</code>（不上传）。'}</p>
      </form>`

  // 本地模式：上传项目文件夹（浏览器选文件夹 → 仅发送源码/配置到本机服务扫描）
  const localForms = local ? `
      <form id="dirform">
        <label>选择项目文件夹，开始体检</label>
        <input type="file" id="dir" webkitdirectory directory multiple>
        <button id="dbtn" type="submit">开始体检 →</button>
        <div id="status" class="status"></div>
        <p class="hint">📂 选你的项目文件夹即可。浏览器可能提示"上传 N 个文件"——<b>实际只发送源码/配置（自动跳过 node_modules、图片、超大文件），且只到本机的本地服务、不出本机</b>。</p>
      </form>
      <details class="alt"><summary>或：体检公开仓库 URL</summary>${urlForm}</details>` : ''

  return page('ShellWard 合规体检', `
    <nav class="nav">
      <div class="logo">🛡️ Shell<span>Ward</span> <em>合规网关</em></div>
      <a class="ghbtn" href="https://github.com/jnMetaCode/shellward" target="_blank">★ GitHub Star</a>
    </nav>
    <main class="wrap">
      <header class="hd">
        <div class="tag">网安法 2026 · PIPL · 等保2.0 · 数据出境 · AI标识</div>
        <h1>30 秒，查出你的 AI 项目<br>踩了哪些 <span class="hl">中国合规红线</span></h1>
        <p class="sub">数据出境 · 硬编码密钥 · 个人信息暴露 —— 精确到 <code>文件:行</code>，并给出境内替代建议。${local ? '<b>私有代码不出本机。</b>' : ''}</p>
      </header>

      <section class="card">
        ${local ? localForms : urlForm}
      </section>

      <section class="checks">
        <div class="chk"><span>🌐</span><b>数据出境</b><i>境外大模型端点/SDK</i></div>
        <div class="chk"><span>🔑</span><b>硬编码密钥</b><i>OpenAI/GitHub/AWS…</i></div>
        <div class="chk"><span>🪪</span><b>个人信息</b><i>身份证/手机/银行卡</i></div>
        <div class="chk"><span>📂</span><b>.env 暴露</b><i>权限/明文密钥</i></div>
      </section>

      <p class="demo">🤔 想先看效果？ <a href="/demo">▶ 看一个含风险的示例报告</a></p>

      <section class="trust">
        <div><b>🔒 ${local ? '不出本机' : '不存储代码'}</b>${local ? '服务端直读本机，零上传' : '公开仓库浅克隆，用完即删'}</div>
        <div><b>📦 零依赖</b>可在信创/离线环境跑</div>
        <div><b>⚖️ 开源</b>Apache-2.0，代码全公开</div>
        <div><b>🇨🇳 中文优先</b>为中国监管而生</div>
      </section>

      <footer class="ft">
        公众号「AI不止语」· 技术问答 · 实战文章&nbsp;&nbsp;|&nbsp;&nbsp;
        <a href="https://github.com/jnMetaCode/shellward" target="_blank">github.com/jnMetaCode/shellward</a> · Apache-2.0
      </footer>
    </main>
    <div id="overlay" class="overlay"><div class="spin"></div><div id="ovtext">扫描中…</div></div>
    ${local ? UPLOAD_SCRIPT : ''}`)
}

// 本地：统一路径栏 + 目录浏览器。粘贴路径 / 点选填充 → 服务端直接扫（零上传，跳过 node_modules）
const BROWSE_SCRIPT = `<script>
(function(){
  var pb=document.getElementById('pathbar'), sb=document.getElementById('scanbtn'), ul=document.getElementById('dirs');
  function render(d){
    if(d.error){ ul.innerHTML='<li class="empty">无法读取：'+d.error+'</li>'; return; }
    if(typeof d.current==='string') pb.value=d.current;
    ul.innerHTML='';
    if(d.parent){ var up=document.createElement('li'); up.className='up'; up.textContent='⬆ 上级目录'; up.onclick=function(){load(d.parent)}; ul.appendChild(up); }
    if(!d.dirs.length){ var e=document.createElement('li'); e.className='empty'; e.textContent='（无子文件夹，可直接点"体检"扫此目录）'; ul.appendChild(e); }
    d.dirs.forEach(function(name){ var li=document.createElement('li'); li.textContent='📁 '+name;
      li.onclick=function(){ load((pb.value||'').replace(/\\/+$/,'')+'/'+name) }; ul.appendChild(li); });
  }
  function load(dir){ fetch('/browse?dir='+encodeURIComponent(dir||'')).then(function(r){return r.json()}).then(render).catch(function(e){ ul.innerHTML='<li class="empty">错误：'+e+'</li>'; }); }
  function scan(){ var p=(pb.value||'').trim(); if(!p){ pb.focus(); return; } document.getElementById('overlay').style.display='flex'; window.location.href='/scan?path='+encodeURIComponent(p); }
  sb.onclick=scan;
  pb.addEventListener('keydown', function(e){ if(e.key==='Enter'){ e.preventDefault(); load(pb.value); } });
  load(''); // 从家目录起
})();
</script>`

// （旧上传脚本保留备用，当前本地模式改用目录浏览器）
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
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:linear-gradient(180deg,#f4f7fb,#e8edf4);color:#0f172a;
font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
a{color:#cb0000;text-decoration:none}
.nav{display:flex;justify-content:space-between;align-items:center;max-width:760px;margin:0 auto;padding:18px 24px}
.logo{font-weight:800;font-size:17px}.logo span{color:#cb0000}
.logo em{font-style:normal;color:#94a3b8;font-weight:600;font-size:13px;margin-left:5px}
.ghbtn{border:1px solid #cbd5e1;border-radius:8px;padding:7px 14px;font-size:13px;font-weight:700;color:#0f172a;background:#fff;transition:.15s}
.ghbtn:hover{border-color:#cb0000;color:#cb0000}
.wrap{max-width:760px;margin:0 auto;padding:0 24px 48px}
.hd{text-align:center;padding:22px 0 26px}
.tag{display:inline-block;background:#fef2f2;color:#cb0000;font-size:12px;font-weight:700;padding:5px 14px;border-radius:999px;margin-bottom:16px}
h1{font-size:34px;line-height:1.25;margin:0 0 12px;letter-spacing:-.6px}
h1 .hl{color:#cb0000}
.sub{color:#475569;font-size:16px;max-width:580px;margin:0 auto}
.sub code{background:#eef2f7;padding:1px 6px;border-radius:5px;font-size:14px}
.card{background:#fff;border-radius:16px;padding:24px 26px;box-shadow:0 10px 30px rgba(15,23,42,.10);border-top:3px solid #cb0000}
form{display:flex;flex-direction:column;gap:10px;text-align:left}
label{font-size:13px;font-weight:700;color:#334155}
input{padding:14px 16px;border:1px solid #cbd5e1;border-radius:10px;font-size:15px;width:100%}
input:focus{outline:none;border-color:#cb0000;box-shadow:0 0 0 3px rgba(203,0,0,.12)}
button{background:#cb0000;color:#fff;border:0;border-radius:10px;padding:14px;font-size:16px;font-weight:700;cursor:pointer;transition:.15s}
button:hover{background:#a80000}button:disabled{background:#94a3b8;cursor:default}
/* 文件夹选择：虚线投放区 + 红色按钮 */
input[type=file]{width:100%;padding:22px 16px;border:2px dashed #cbd5e1;border-radius:12px;background:#f8fafc;cursor:pointer;font-size:14px;color:#64748b;transition:.15s}
input[type=file]:hover{border-color:#cb0000;background:#fff}
input[type=file]::file-selector-button{background:#cb0000;color:#fff;border:0;border-radius:8px;padding:9px 18px;margin-right:14px;font-weight:700;font-size:14px;cursor:pointer}
input[type=file]::file-selector-button:hover{background:#a80000}
.status{display:none;margin:10px 0 0;padding:10px 14px;border-radius:8px;background:#f1f5f9;color:#334155;font-size:13.5px;border-left:3px solid #cb0000}
.hint{font-size:12.5px;color:#64748b;margin:8px 0 0;line-height:1.55}
code,.hint code{background:#eef2f7;padding:1px 6px;border-radius:5px;font-size:12.5px}
.pathrow{display:flex;gap:8px;margin-top:6px}
.pathrow input{flex:1;font-family:ui-monospace,Menlo,monospace;font-size:13px}
.pathrow button{padding:14px 22px;white-space:nowrap}
.browser{border:1px solid #e2e8f0;border-radius:10px;overflow:hidden;margin:10px 0 0;text-align:left}
.dirs{list-style:none;margin:0;padding:0;max-height:200px;overflow-y:auto}
.dirs li{padding:9px 14px;border-top:1px solid #eef2f7;cursor:pointer;font-size:14px}
.dirs li:first-child{border-top:0}.dirs li:hover{background:#f8fafc}
.dirs li.up{color:#cb0000;font-weight:600}.dirs li.empty{color:#94a3b8;cursor:default;font-size:13px}
details.alt{margin:14px 0 0;border-top:1px dashed #e2e8f0;padding-top:12px}
details.alt summary{cursor:pointer;color:#cb0000;font-size:13px;font-weight:600}
details.alt[open] summary{margin-bottom:10px}
.checks{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:22px 0}
.chk{background:#fff;border:1px solid #eef2f7;border-radius:12px;padding:16px 10px;text-align:center}
.chk span{font-size:24px;display:block;margin-bottom:6px}
.chk b{display:block;font-size:14px}.chk i{font-style:normal;color:#94a3b8;font-size:11px;display:block;margin-top:3px}
.demo{text-align:center;font-size:13.5px;color:#475569;margin:6px 0 22px}.demo a{font-weight:700}
.trust{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0 0 26px}
.trust div{background:#f8fafc;border-radius:10px;padding:14px 12px;font-size:11.5px;color:#64748b;line-height:1.5}
.trust b{display:block;color:#0f172a;font-size:13px;margin-bottom:3px}
.ft{text-align:center;color:#94a3b8;font-size:12.5px;padding-top:14px;border-top:1px solid #e3e9f1}
.overlay{display:none;position:fixed;inset:0;background:rgba(15,23,42,.6);z-index:99;
flex-direction:column;align-items:center;justify-content:center;color:#fff;gap:16px;font-size:15px;font-weight:600}
.spin{width:46px;height:46px;border:4px solid rgba(255,255,255,.25);border-top-color:#fff;border-radius:50%;animation:sp .8s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
/* 错误页复用 */
.hero{background:#fff;max-width:520px;margin:60px auto;padding:36px;border-radius:16px;box-shadow:0 10px 30px rgba(15,23,42,.1);text-align:center}
.hero .logo{font-size:15px}.back{font-weight:600}
@media(max-width:560px){h1{font-size:26px}.checks,.trust{grid-template-columns:repeat(2,1fr)}}
</style></head><body>${body}</body></html>`
}

function esc(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}
