# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
