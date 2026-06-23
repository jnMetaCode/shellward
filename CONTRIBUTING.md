# 贡献指南 · Contributing

欢迎参与 ShellWard！无论是修 bug、补检测规则，还是加一个境内大模型，都非常欢迎。
Contributions welcome — bug fixes, new detection rules, or adding a domestic model all help.

ShellWard 是一个**面向中国监管的 AI 应用合规网关**：静态体检（数据出境 / 密钥 / 个人信息）+ 运行时防护（注入 / 外泄拦截）。零依赖、TypeScript。

## 新手最容易上手的地方（good first issue）

不用懂全部架构，下面这些是「改数据 / 加一条规则」级别的，最适合第一次贡献：

| 想做的 | 改哪个文件 | 说明 |
|---|---|---|
| **加一个境内大模型**到替代建议 | `src/rules/domestic-alternatives.ts` | 在 `DOMESTIC_MODELS` 加一项（名称 / 厂商 / OpenAI 兼容 base_url） |
| **加一个境外厂商 / SDK**识别 | `src/rules/overseas-llm.ts` | 在 `OVERSEAS_LLM_ENDPOINTS` 或 `OVERSEAS_LLM_PACKAGES` 加一项 |
| **加一条提示注入规则** | `src/rules/injection-zh.ts` / `injection-en.ts` | 含 `id` / `name` / `pattern` / `riskScore` / `category` |
| **加一个合规控制项** | `src/compliance/regulations.ts` | 对应一条法规条款 + 双语 + 整改建议 |
| **给检测基准补样例** | `bench/scan-bench.ts` | 加正例 / 硬负例，跑 `npm run bench:scan` 验证 |

## 开发流程

```bash
npm install          # 仅 devDependencies（运行时零依赖）
npm run build        # tsc 编译
npm test             # 全套测试（必须全绿才合并）
npm run bench:scan   # 合规扫描检测基准（精确率 / 召回率门禁）
```

1. Fork → 建分支 `git checkout -b feat/xxx`
2. 改动 + **补测试**（`test-*.ts`）
3. `npm test` 全绿
4. 提 PR，说明动机与用例

## 约定 · Conventions

- **TypeScript，零外部依赖** —— 只用 Node 内置模块
- 面向用户的文案**中英双语（中文优先）**；检测规则需 `description_zh` + `description_en`
- 正则统一加 `/i`（不区分大小写），并避免 ReDoS（见 `test-redos.ts`）
- **诚实优先**：静态扫描查不了的运行时项标「待核验」而非虚报「已合规」；不夸大、可逐行核对
- 安全漏洞请走 [SECURITY.md](SECURITY.md)，不要开公开 issue

## 想加大功能？

先开一个 issue 讨论（带 `enhancement` 标签），说清用例。例如 policy-as-code 的扩展（按路径 / 按作者的规则）见 [#2](https://github.com/jnMetaCode/shellward/issues/2)。

## License

贡献即表示同意以 Apache-2.0 协议授权。By contributing, you agree your contributions are licensed under Apache-2.0.

谢谢你让 ShellWard 更好用。🙏
