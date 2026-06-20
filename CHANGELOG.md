# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.7.9] - 2026-06-20

### Changed — 「待确认」不再啰嗦/吓人
- 静态扫描的 ⚪ 待核验项**不再每行重复**"ShellWard 运行时可提供…静态扫描无法验证"长句（此前 12 行同一句）
- 改为在「合规控制项明细」区块**开头统一说明一次**：**⚪ 待核验 ≠ 不合规**，它们是运行时合规控制（审计留存/内容过滤/注入拦截/数据外发管控），静态扫描判断不了，需部署 ShellWard 运行时或人工核验
- 每个 ⚪ 行只保留"该做什么"（整改建议），更清爽
- HTML 报告加蓝色说明条；终端/markdown 同步

## [0.7.8] - 2026-06-20

### Changed — 本地客户端改用「目录浏览器」，彻底解决上传 3 万文件的问题
- **本地模式不再用浏览器文件夹上传**（webkitdirectory 会读取整个 node_modules，弹"上传 3 万+ 文件"、又慢又吓人）
- 改为**服务端目录浏览器** `/browse`（仅本地模式）：在网页里点进本机文件夹 → 服务端**直接读取本机文件扫描**，**零上传、不出本机、自动跳过 node_modules**
- 公网模式禁止 `/browse`（防止扫服务器硬盘），返回 403
- 配合 0.7.7 跳过 `release/*.app` 构建产物，长路径不再压坏报告表格
- `test-web.ts` 扩至 20 项（含目录浏览 + 公网拒绝浏览）；全套 **302 测试**全绿

## [0.7.7] - 2026-06-20

### Fixed — 真实项目扫描的两个问题（用户实测发现）
- **跳过构建产物**：新增跳过 `release/`/`releases/`、`*.app`/`*.framework`/`*.bundle` 等打包目录——此前会扫进 Electron 打包的 `*.app` 里重复的 package.json，造成重复发现 + 超长路径
- **修复长路径压坏报告表格**：超长文件路径曾把"说明/严重度"列挤成竖排单字；改为路径可换行 (`word-break`) + 固定列宽
- 实测 agency-orchestrator：去噪后 11 个数据出境点均落在真实源码 + 1 个真实手机号泄露（输出文件），无构建产物噪声

## [0.7.6] - 2026-06-20

### Added — 让"检查过程"可见（回应"秒出=没检查吗"）
- **空结果也展示检查过程**：未发现风险时不再只说"未发现"，而是逐项列出查了什么（境外端点+SDK依赖38特征 / 硬编码密钥 / 中文+国际PII / .env权限）+ ✓0命中 + 文件数/规则数/耗时——证明确实逐项扫了
- **内置"含风险示例"一键演示** (`/demo` + 首页按钮)：扫一个故意埋了风险的样例项目，同样秒出但满屏发现(境外5/密钥6/PII4 + 行号)，直观证明"快≠假"
- 验证：独立 grep 确认真实干净项目(superpowers-zh)无风险→报0正确；往副本植入密钥→立刻命中 file:line

## [0.7.5] - 2026-06-20

### Fixed — web 客户端"扫不了"的真实 bug（用户反馈后修）
- **客户端文件过滤未对齐服务端**：上传时漏掉 `.md`/`.mdx`/`.ipynb` 等，导致 markdown 为主的项目（如 prompt/skill 库）被全滤光、提示"未找到可扫描文件"。现与服务端 SCAN_EXT 对齐
- **结果渲染从 `document.write` 改为 Blob URL 跳转**，更可靠（此前某些情况报告写不出、页面像卡住）
- **加可见状态提示**：读取/扫描/失败都在页面显示（不再静默失败或只弹 alert）
- 新增 `test-web.ts`（18 项端到端集成测试：上传扫描、本地路径、URL 校验、路径穿越防护、双模式权限），纳入 `npm test`
- 全套 **300 测试**全绿

## [0.7.4] - 2026-06-20

### Added — 合规扫描检测基准（把"信我能检"变成"看数字"）
- `bench/scan-bench.ts` + `npm run bench:scan`：用 **31 个标注样例**（17 真实风险 + 14 硬负例：境内端点/占位符/文档示例/lock/无效校验位）跑**真实 scanProject 管线**，算精确率/召回率/F1，CI 门禁（低于 90% 失败）
- 基线：**精确率 100% · 召回率 100% · F1 100%**
- 建基准过程即暴露并验证了占位符过滤器的边界（含 `abcdef`/`123456` 的密钥会被当示例滤掉——偏向精确率的有意取舍）
- README「Detection Benchmark」新增合规扫描一行（诚实标注为自建语料）

## [0.7.3] - 2026-06-20

### Added — 扫描透明度（"秒出=干活了吗"的证据）
- 报告显示**扫描耗时 + 应用的检测规则数**（如"已扫描 150 个文件 · 耗时 28ms · 应用 53 条检测规则"）——让"快"可被验证：正则匹配文本本就是毫秒级，快≠假
### Fixed
- 数据出境控制项不再把同一厂商列两次（端点命中 + SDK 依赖命中去重，不区分大小写）

## [0.7.2] - 2026-06-20

### Changed — 诚实度与真实覆盖（用户反馈"上传就出结果太假"后修正）
- **静态扫描不再报"优秀/A"式合规结论**：以「项目实测风险」为主指标（未发现/发现 N 项），得分降为"可观测项"次要参考，并明确标注「X 项合规控制项未验证、非完整合规结论」（终端 + HTML 一致）
- **扫描 `.md`/`.mdx`/`.ipynb` 等**：此前完全跳过 markdown，导致 prompt/skill 类项目"没真扫到正文"。现纳入扫描（superpowers-zh 扫描文件数 74→150）
- **Markdown 文档只检测境外端点、跳过密钥/PII 模式**：避免把 README「检测示例」里的演示密钥/SSN 误报为真实风险（ShellWard 自扫从误报回到 0）
- **Web URL 扫描健壮性**：克隆超时 30s→60s、并发 2→4、大仓库/超时给友好提示（引导用本地客户端选文件夹）、URL 表单加"扫描中"状态防重复点击导致 503
- `test-compliance.ts` 扩至 94 项；全套 **282 测试**全绿

## [0.7.1] - 2026-06-20

### Changed — 本地客户端 UX：选文件夹上传（不再手敲路径）
- 本地模式（`shellward web --local`）首页改为：**「选择项目文件夹」**（浏览器读取→仅发送到本机本地服务→扫描）+ 「公开仓库 URL」双入口，不必再手敲路径
- 文件夹上传客户端侧过滤（跳过 node_modules/.git 等、仅文本/配置、单文件 512KB、总量 8MB、≤3000 文件），数据**不经过任何外部服务器、不出本机**
- 新增 `POST /scan-files`（仅本地模式）：路径穿越防护（拒绝绝对路径/`..`，限制写入临时目录内）、16MB 上限、用完即删
- 用户反馈"填路径不好填"后改进

## [0.7.0] - 2026-06-20

### Added — Web 扫描器 / 客户端（双模式，一套代码）
- **`shellward web [port]`（公网模式）**：网页贴「公开仓库 URL」或访问 `/scan?repo=URL` 链接 → 服务端浅克隆 + 扫描 + 出报告。公开仓库代码本就公开，不涉数据出境
- **`shellward web --local`（客户端模式，仅 127.0.0.1）**：浏览器 GUI 填本地路径扫描，私有代码不上传、不出本机——零 Electron 的「客户端」体验
- 安全加固：域名白名单（github/gitlab/gitee/bitbucket）、严格 URL 正则（拒凭据/注入字符）、浅克隆 `--depth 1` + `GIT_TERMINAL_PROMPT=0` + 30s 超时、临时目录用完即删、并发上限、**绝不执行仓库代码**、**公网模式禁止本地路径扫描**
- 附 `Dockerfile`，可一键部署到任意容器平台
- `test-compliance.ts` 扩至 85 项（含 10 项 URL 安全校验）；全套 **273 测试**全绿

## [0.6.9] - 2026-06-20

### Changed — HTML 报告视觉重做（专业 UI）
- **环形评分仪表**（conic-gradient，按等级着色）替代原扁平数字
- **语义化状态药丸**（合规/部分/不合规/待确认）+ **severity 彩色标签**（严重/高/中）
- **卡片化法规分组**（每组带 pass/fail 迷你计数）、概览 chips、统计卡
- 品牌色克制使用、清晰层级、表格 hover、移动端响应式、打印优化
- 顾问态（⚪）文案弱化处理，降低视觉噪声；自包含、零依赖不变

## [0.6.8] - 2026-06-20

### Added — 本地 web 视图（方便看，数据不出本机）
- **`npx shellward scan --open`**：扫描后把 HTML 合规报告写入临时目录并在默认浏览器打开
- **`npx shellward scan --serve [port]`**：本地零依赖 HTTP 服务（默认 7777，仅监听 127.0.0.1）提供报告，自动打开浏览器
- 坚持"数据不出本机"原则：**不做云端上传扫描**，只在本地起服务/打开文件查看
- 真实第三方项目狗粮验证：非 AI 库（chalk）0 误报、Python AI 项目（openai-quickstart）正确检出依赖

## [0.6.7] - 2026-06-20

### Changed
- **README 中文优先**：第一屏改为中文标题/定位/「30 秒合规体检」，英文降为 `## English` 章节（项目面向中国市场，理应中文打头）
- **修复 `.env.example` 误报**：`.env.example` / `.sample` / `.template` / `.dist` 等模板文件不再报"权限过宽"（它们本就该提交、不含真实密钥）——真实第三方项目实测发现
- `test-compliance.ts` 扩至 75 项（含 .env 模板回归）；全套 **263 测试**全绿

## [0.6.6] - 2026-06-20

### Changed — 诚信：静态扫描不再虚报"已合规"
- 体检区分**「已部署运行时」与「静态扫描」**两种上下文（`runComplianceAudit` 增 `opts.deployed`，默认 true）
- `npx shellward scan`（静态扫描，未部署 ShellWard 运行时）下，**能力层 / 审计类控制项不再判为 ✅ "已启用"**，改为 ⚪「ShellWard 运行时可提供，静态扫描无法验证」——避免给用户虚假的合规安心
- 仅 env 可观测项（境外端点/依赖、是否 root）如实评估；得分基于真实证据
- MCP / 插件上下文（ShellWard 实际在运行）保持如实"已启用"
- CLI footer 明确：得分仅反映可静态观测的项目风险，⚪ 项需运行时部署或人工核验
- `test-compliance.ts` 扩至 74 项；全套 **262 测试**全绿

## [0.6.5] - 2026-06-20

### Changed — 扫描器精度（降"狼来了"误报）
- **占位符 / 示例值过滤**：密钥类发现若值或所在行是明显占位符（`example` / `your-api-key` / `changeme` / `xxxx` / `<...>` / `AKIA...EXAMPLE` 等）则不再报为风险
- **默认跳过噪声文件**：`package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` / `*.min.js` / `*.map` / `*.snap`（不含密钥，只制造误报）
- **`.shellwardignore`**：gitignore 风格的扫描排除（`dir/`、`*.ext`、精确路径），让用户排除测试桩/示例
- 仓库内置 `.shellwardignore` 示例；**ShellWard 自扫从 96 个误报降到 0**（不再对自己"狼来了"）
- `test-compliance.ts` 扩至 68 项；全套 **256 测试**全绿

## [0.6.4] - 2026-06-20

### Added
- **HTML 合规报告导出** (`src/compliance/html-report.ts`): `npx shellward scan --html report.html` 生成自包含、内联样式、零依赖的专业合规报告——可浏览器打开、打印成 PDF、用于等保/PIPL **备案与审计存档**。面向法务/合规/测评机构（终端输出之外的第二受众）
- 评分仪表、项目实测风险表、境内替代建议、按法规分组的控制项表、免责声明，全部 HTML 转义防注入
- `test-compliance.ts` 扩至 63 项；全套 **251 测试**全绿

## [0.6.3] - 2026-06-20

### Added
- **境内合规替代建议（处方）** (`src/rules/domestic-alternatives.ts`): 扫到境外大模型（端点/SDK 依赖）时，自动给出境内已备案模型替代方案（通义千问 DashScope / DeepSeek / Kimi / 智谱 GLM / 豆包 / 文心）及其 OpenAI 兼容 `base_url` 与迁移难度。把"数据出境风险"变成可执行的迁移路径——`openai` SDK 项目通常只需改 `base_url`+`key`、代码零改动
- 报告新增「境内合规替代建议」段（`/compliance`、`compliance_check`、`npx shellward scan` 均含）
- `test-compliance.ts` 扩至 54 项；全套 **242 测试**全绿

## [0.6.2] - 2026-06-20

### Added — 中国 AI 合规网关方向（合规体检 + 项目扫描 + 零安装 CLI）
- **合规体检引擎** (`src/compliance/`): 把网安法 / PIPL / 等保2.0 / 数据出境 / AI标识 的 14 条可核查控制项结构化，跑出红黄绿评分卡（`regulations.ts` + `audit.ts` + `report.ts`）
- **项目真实风险扫描** (`src/compliance/project-scan.ts`): 零依赖遍历项目，检测境外大模型端点与 **SDK 依赖**（数据出境）、硬编码密钥、文件中的中文 PII、`.env` 权限，输出 `文件:行` 级发现
- **境外大模型识别** (`src/rules/overseas-llm.ts`): 端点 + 依赖清单（package.json / requirements.txt / pyproject.toml / go.mod）双路识别 OpenAI/Anthropic/Gemini 等 = 数据出境（中国差异化能力）
- **零安装 CLI** (`src/cli.ts`): `npx shellward scan` 30 秒出"关于你项目"的合规评分卡；`--json` / `--ci` / `--out <file>` 导出；`shellward mcp` 子命令向后兼容
- **发现驱动评分**: 项目实测风险按严重度扣分（封顶 40），分数反映真实风险而非自检开关
- **MCP 工具 `compliance_check`** 与 **命令 `/compliance`**
- **GitHub Action** (`action.yml`): PR 合规门禁，发现 critical 时让构建失败
- `test-compliance.ts`（45 项合规测试）

### Changed
- `bin.shellward` 指向新 CLI (`dist/cli.js`)；`shellward-mcp` 仍指向 MCP server（向后兼容）
- README 第一屏重写为"AI 合规网关"叙事，主推 `npx shellward scan`

## [0.6.1] - 2026-06-05

### Fixed
- **Input robustness (fail-safe)**: every public engine method (`checkCommand`, `checkInjection`, `scanData`, `checkTool`, `checkPath`, `checkResponse`, `checkAction`, `checkOutbound`, `scanToolDefinition`, `extractTextFields`) now coerces hostile/garbage input (`null`, `undefined`, numbers, objects) instead of throwing — a security check must never crash on the input it inspects. Found by an adversarial QA pass; locked in with regression tests.

## [0.6.0] - 2026-06-05

### Added
- **MCP tool-poisoning scanner** (`scanToolDefinition` / `scan_mcp_tool` MCP tool): detects hidden instructions, invisible characters, concealment ("don't tell the user"), sensitive-file access and exfiltration hints in an MCP tool's description/parameters
- **MCP rug-pull detection** (`McpBaseline`): fingerprints each tool's description+schema and flags silent changes across runs (`SHELLWARD_BASELINE_PATH` to relocate the store)
- **`/scan-mcp` command + MCP client** (`mcp-client.ts`): discovers configured MCP servers and scans them live — **stdio and remote Streamable-HTTP** (incl. SSE responses + session headers), zero dependencies
- **Custom rules** (`customRules` in `ShellWardConfig`): additive `blockedTools` / `sensitiveTools` / `outboundTools` / `honeypotPaths` / `sensitivePatterns` / `dangerousCommands` / `injectionRules`, plus `allowedTools` that always wins; invalid user regexes are skipped, never throw
- **Detection benchmark** (`bench/`, `npm run bench`): labeled corpus (attacks + hard negatives + documented bypasses) reporting precision/recall/F1; CI regression gate (`--ci`)
- **ReDoS audit** (`test-redos.ts`, in CI): adversarial-input timing budget for every detector
- Unicode tag-character and variation-selector detection in hidden-char scanning
- Startup nudge to run `/scan-mcp` when MCP servers are configured

### Changed
- **Default `injectionThreshold` 60 → 40** — the benchmark showed 60 missed most single-signal attacks (injection recall 37.5% → 100%). More aggressive blocking; revert via config or `SHELLWARD_THRESHOLD`
- Injection rules 32 → 37 (20 ZH + 17 EN); fixed several intervening-word / reversed-order / word-boundary bugs
- Command + injection inputs are normalized before matching (empty-quote de-obfuscation, zero-width stripping)
- L5 Security Gate now delegates outbound DLP to the single L7 path (no divergence)

### Fixed
- **ReDoS**: `splitCommands` (catastrophic backtracking on whitespace floods) and `zh_mixed_lang_injection` (unbounded `.*`)
- **PII false positives**: `phone_cn` restricted to real carrier segments; `bank_card_cn` narrowed to UnionPay (no longer mislabels Visa/Mastercard)
- `SECURITY.md` corrected (no false "no network calls" claim; supported versions; ReDoS claim now CI-verified)

## [0.5.16] - 2026-04-15

### Added
- 支持平台表新增 **Hermes Agent**（Nous Research，通过 MCP 接入）

### Fixed
- `test-mcp.ts` 改为 NDJSON framing，与 server 对齐（此前 0/11，现在 11/11 全通过）

### Changed
- `CURRENT_VERSION` 同步到 0.5.16（此前滞留 0.5.10）

## [0.5.0] - 2026-03-14

### Added
- **ShellWard Core Engine** (`src/core/engine.ts`): Platform-agnostic AI Agent Security Middleware
- **SDK 模式**: `import { ShellWard } from 'shellward'` — 任意 AI Agent 平台可用
- **Windows 兼容**: 使用 `os.homedir()` 替代 `process.env.HOME`，支持 Windows
- **npm scripts**: `npm run test` 运行全部 112 项测试

### Changed
- **L2/L6 审计模式**: PII 仅检测并记录审计，不再脱敏 — 内部使用允许，L7 拦截外泄
- **架构重构**: OpenClaw 层改为薄适配器，核心逻辑集中在 engine.ts
- **README**: 更新为审计模式说明，移除脱敏误导
- **package.json**: 增加 exports、scripts，描述对齐定位文档

### Fixed
- tool-blocker: file_delete 正确传入 operation='delete'
- update-check: writeCache 前确保目录存在
- test-integration: 审计日志路径使用 homedir() 兼容 Windows

## [0.3.0] - 2026-03-12

### Added
- **L6 Outbound Guard**: Redacts PII from LLM responses via `message_sending` hook
- **L7 Data Flow Guard**: Detects data exfiltration chains (read sensitive file → send via network)
- **L8 Session Guard**: Session security audit + subagent monitoring
- **Canary tokens**: Injected in system prompt to detect prompt exfiltration
- **6 slash commands**: `/security`, `/audit`, `/harden`, `/scan-plugins`, `/check-updates`, `/cg`
- **Security guide skill**: Interactive deployment security assessment (`/security-guide`)
- Supply chain detection: Package install command monitoring
- Suspicious URL parameter detection

### Changed
- L1 Prompt Guard now uses `prependSystemContext` for prompt caching (saves tokens)
- Data flow guard Map capped at 500 entries to prevent memory exhaustion
- Audit log now outputs to stderr on write failures
- Security gate rejects empty action parameters

### Fixed
- Tool blocker: Added typeof check for command parameters
- chmod 777 regex now matches at end of string
- All type definitions updated for L6/L7/L8 layers

## [0.2.0] - 2026-03-11

### Added
- 13th Chinese injection rule: XML tag injection detection
- SSN validator to reject date-like false positives
- `splitCommands()` for command chaining attack detection (`;`, `&&`, `||`)
- Path normalization via `resolve()` to prevent `../` traversal bypass

### Fixed
- All 15 dangerous command patterns: added case-insensitive `/i` flag
- All 12 protected path patterns: added case-insensitive `/i` flag
- L1 return type: `prependSystemContext` instead of `systemPrompt`
- L2 event structure: `event.message.content[]` array processing
- L3/L4 field names: `event.toolName`/`event.params` per OpenClaw API
- Config validation: mode, locale, and threshold clamping

## [0.1.0] - 2026-03-11

### Added
- Initial release with 5 defense layers (L1-L5)
- L1 Prompt Guard: Security rules injection via `before_prompt_build`
- L2 Output Scanner: PII/secret redaction via `tool_result_persist`
- L3 Tool Blocker: Dangerous command/path blocking via `before_tool_call`
- L4 Input Auditor: Prompt injection detection (12 EN + 12 ZH rules)
- L5 Security Gate: Defense-in-depth tool via `registerTool`
- Chinese PII detection: ID card (checksum), phone, bank card (Luhn)
- Global PII detection: API keys, JWT, passwords, SSN, credit cards, emails
- 15 dangerous command rules
- 12 protected path rules
- JSONL audit log with 100MB auto-rotation
- Bilingual support (EN/ZH) with auto-detection
- Dual mode: enforce (block+log) / audit (log only)
