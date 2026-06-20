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
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root: v.url, backLink: '/' }))
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
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root, backLink: '/' }))
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
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root: rootName, backLink: '/' }))
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
    send(res, 200, 'text/html', renderHtmlReport(report, scan, locale, { root: '示例项目（含风险）/ demo-ai-app', backLink: '/' }))
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
        <label>${local ? '③ ' : ''}公开仓库地址</label>
        <input name="repo" placeholder="https://github.com/owner/repo"${local ? '' : ' autofocus'}>
        <button type="submit">${local ? '体检该仓库 →' : '开始体检 →'}</button>
        <p class="hint">仅支持公开仓库（GitHub / GitLab / Gitee / Bitbucket）。大仓库可能超时——${local ? '此时用上方「上传文件夹」更稳。' : '<b>大仓库 / 私有代码请用本地客户端或 CLI</b>：<code>npx shellward web --local</code> / <code>npx shellward scan</code>（不上传）。'}</p>
      </form>`

  // 本地模式：① 上传文件夹（一次选定，最方便）  ② 点选文件夹（零上传）  ③ URL
  const localForms = local ? `
      <form id="dirform">
        <label>① 上传项目文件夹（最方便）</label>
        <input type="file" id="dir" webkitdirectory directory multiple>
        <button id="dbtn" type="submit">开始体检 →</button>
        <div id="status" class="status"></div>
        <p class="hint">选你的项目文件夹即可。<b>浏览器可能提示"上传 N 个文件"——放心：实际只发送源码/配置（自动跳过 node_modules、图片、超大文件），且只到<u>本机的本地服务</u>，不出本机。</b></p>
      </form>
      <details class="alt"><summary>不想上传？点选文件夹（零上传）</summary>
        <label>② 在本机点选项目文件夹（零上传）</label>
        <div class="browser">
          <div class="bpath" id="curpath">加载中…</div>
          <ul class="dirs" id="dirs"></ul>
        </div>
        <button id="scanbtn" type="button">✅ 扫描当前文件夹 →</button>
        <p class="hint">服务端直接读取本机文件、零上传、不出本机，自动跳过 node_modules。</p>
      </details>
      <div class="or">— 或 —</div>` : ''

  return page('ShellWard 合规体检', `
    <div class="hero">
      <div class="logo">🛡️ Shell<span>Ward</span> 合规网关</div>
      <h1>AI 应用合规体检</h1>
      <p class="sub">${local ? '上传/点选项目文件夹，或贴公开仓库链接' : '贴公开仓库链接'}，30 秒查出数据出境 / 硬编码密钥 / 个人信息暴露等中国合规红线。</p>
      ${localForms}
      ${urlForm}
      <p class="demo">🤔 觉得"秒出"不真？ <a href="/demo">▶ 看一个含风险的示例报告</a>（同样秒出，但满屏发现 + 行号）</p>
      <p class="foot">网安法 2026 · PIPL · 等保2.0 · 数据出境 · AI标识 ｜ 零依赖 · 开源 ·
        <a href="https://github.com/jnMetaCode/shellward">GitHub ⭐</a></p>
    </div>
    ${local ? UPLOAD_SCRIPT + BROWSE_SCRIPT : ''}`)
}

// 本地目录浏览器：点选文件夹 → 服务端直接扫（零上传，不读 node_modules）
const BROWSE_SCRIPT = `<script>
(function(){
  var cur='';
  function load(dir){
    var cp=document.getElementById('curpath'); if(cp)cp.textContent='加载中…';
    fetch('/browse?dir='+encodeURIComponent(dir||'')).then(function(r){return r.json()}).then(function(d){
      if(d.error){ if(cp)cp.textContent='无法读取：'+d.error; return; }
      cur=d.current; if(cp)cp.textContent=cur;
      var ul=document.getElementById('dirs'); if(!ul)return; ul.innerHTML='';
      if(d.parent){ var up=document.createElement('li'); up.className='up'; up.textContent='⬆ 上级目录'; up.onclick=function(){load(d.parent)}; ul.appendChild(up); }
      if(!d.dirs.length){ var e=document.createElement('li'); e.className='empty'; e.textContent='（此目录无子文件夹，可直接点上方扫描）'; ul.appendChild(e); }
      d.dirs.forEach(function(name){ var li=document.createElement('li'); li.textContent='📁 '+name; li.onclick=function(){ load(cur.replace(/\\/+$/,'')+'/'+name) }; ul.appendChild(li); });
    }).catch(function(e){ if(cp)cp.textContent='错误：'+e; });
  }
  var sb=document.getElementById('scanbtn');
  if(sb){ sb.onclick=function(){ if(cur){ sb.disabled=true; sb.textContent='扫描中…'; window.location.href='/scan?path='+encodeURIComponent(cur); } }; load(''); }
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
.demo{margin:18px 0 0;font-size:13px;color:#475569}.demo a{font-weight:600}
details.alt{margin:6px 0 10px;text-align:left}
details.alt summary{cursor:pointer;color:#cb0000;font-size:13px;font-weight:600;padding:6px 0}
details.alt[open] summary{margin-bottom:8px}
.browser{border:1px solid #cbd5e1;border-radius:10px;overflow:hidden;margin:4px 0 10px;text-align:left}
.bpath{background:#0f172a;color:#93c5fd;font-family:ui-monospace,Menlo,monospace;font-size:12px;
padding:9px 12px;word-break:break-all}
.dirs{list-style:none;margin:0;padding:0;max-height:240px;overflow-y:auto}
.dirs li{padding:9px 14px;border-top:1px solid #eef2f7;cursor:pointer;font-size:14px}
.dirs li:hover{background:#f1f5f9}
.dirs li.up{color:#cb0000;font-weight:600}
.dirs li.empty{color:#94a3b8;cursor:default;font-size:13px}
.foot{margin:24px 0 0;font-size:12.5px;color:#94a3b8}.foot a,.back{color:#cb0000;text-decoration:none}
.back{font-weight:600}
</style></head><body>${body}</body></html>`
}

function esc(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}
