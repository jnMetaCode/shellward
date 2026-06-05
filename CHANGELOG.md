# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
