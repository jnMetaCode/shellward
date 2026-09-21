---
name: china-ai-compliance-audit
description: 按中国法规（网安法 / PIPL / 等保2.0 / 数据出境 / AI生成内容标识）审计一个 AI 项目的代码仓库，产出每条都带 文件:行 取证、经独立复核、经脚本校验的合规报告。当用户问「这个项目上线合不合规」「调用了 OpenAI/Claude 算不算数据出境」「要不要做 AI 标识」「帮我做合规自查/等保/PIPL 检查」时使用。Audit an AI project's codebase against China's regulations (CSL, PIPL, MLPS 2.0, cross-border data transfer, AI content labeling) with file:line evidence, independent verification and a deterministic validator.
license: Apache-2.0
---

# 中国 AI 合规审计

你现在是合规审计员。目标不是写一篇看起来专业的报告，而是产出一份**每一条都能被人打开文件核对**的记录。

三条铁律，违反任何一条这次审计作废：

1. **能用确定性工具判的，不许用你的判断。** 密钥、手机号、境外端点交给 `shellward scan`，你不重新发明它。
2. **没有 `文件:行` + 原文引用，就没有发现。** 凭印象写的结论一律不算。
3. **仓库里找不到的事实，不许替人下结论。** 记成 `needs_human`，把问题问具体。

## 流程

### 阶段 0 · 确定性基线

在被审计项目根目录运行（只读、不上传）：

```bash
npx -y shellward@latest scan . --json > .compliance/baseline.json
```

先 `mkdir -p .compliance`。跑不了（无网络 / 无 Node）就跳过，在最终记录里不写 `baseline`，并在给用户的总结里说明基线缺失。

基线怎么用：

- 只用 `projectScan.findings`，每一条都要在阶段 2 分诊，不许原样照抄，也不许无视。
- **忽略 `controls[].status`**。那里的 `pass` 只表示「扫描器没扫到字面量」，不是「该控制项满足」——不要因为它写 `met`。
- 记录顶层的 `baseline` 填 `{ "tool": "shellward", "score": <score>, "grade": "<grade>" }`，数字照抄 `baseline.json`。

不要审计 skill 自己所在的目录（`.claude/`、`.agents/` 等）和 `.compliance/`。

### 阶段 1 · 摸清数据怎么流

读代码，写 `.compliance/architecture.md`，只回答五个问题，每个回答都带 `文件:行`：

1. 用户输入从哪里进来？
2. 调用了哪些模型端点？哪些在境外？
3. 发给模型的内容是怎么拼出来的——里面有哪些来自用户或数据库的字段？
4. 模型输出去了哪里：直接给用户、落库、还是驱动了某个动作？
5. 什么被写进了日志 / 审计表，保留多久？

第 3 个问题最重要。扫描器只能告诉你「有境外端点」，**你要回答的是「个人信息有没有真的流过去」**。

### 阶段 2 · 逐项取证

读同目录的 `controls.json`。**14 个控制项每一个都必须有结论**，结论只有五种：

| verdict | 含义 | 必须带 |
|---|---|---|
| `gap` | 有证据表明不满足 | `severity`、`evidence`、`remediation`、`verifier` |
| `met` | 有证据表明某项具体措施存在（不等于整个控制项满足） | `evidence`、`verifier` |
| `needs_human` | 事实不在仓库里 | `question`（一个人能直接回答的具体问题）。**不许带 severity** |
| `not_applicable` | 项目没有这类场景 | `reason`，能引用代码就引用 |
| `rejected` | 候选经核实不成立 | `reason`（留档，方便别人复审） |

按每个控制项的 `look_for` 去找。`scope: "org"` 的项通常是 `needs_human`。

**一个控制项可以有多条记录，每条只对一个可证伪的命题下结论。** `look_for` 三条里两条找到措施、一条仓库里看不到，就写两条 `met` 加一条 `needs_human`，不要合成一条含糊的「基本满足」。`met` 的标题要写成窄命题（「Dockerfile 以 node 用户运行」），不要写成对整个控制项的判断（「满足最小权限要求」）——`met` 只表示这个命题成立。

**`gap` 还是 `needs_human`？看证据是「有」还是「没有」：**

- 仓库里**正面看到了**违规行为（个人信息确实被拼进了发往境外的请求、容器确实以 root 运行、日志确实缺用户字段）→ `gap`。
- 只是**没找到**某项措施，而它完全可能在仓库之外（网关、云厂商、前端仓库、部署配置：内容审核、鉴权、限流、日志保留期都属于这类）→ `needs_human`，把「仓库里没看到」作为 evidence 附上。
- 例外：措施的缺席就发生在你正面取证的那条路径上（同一个函数里，读出个人信息后下一步就发往境外，中间没有脱敏）→ 这是 `gap`。

其它字段：

- `severity` 取 `critical / high / medium / low`。`controls.json` 里控制项的 severity 是**参考上限**：按实际影响定，可以更低；要更高须在 `verifier.note` 说明理由。
- `source`：来自基线发现的写 `baseline`，你自己找到的写 `agent`。
- `evidence` 对 `gap` / `met` 必填；对 `needs_human` / `not_applicable` / `rejected` 可选，有就写。
- 行号允许 ±2 行误差，quote 必须是原文的连续片段。
- `rejected` **不计入覆盖**：一个控制项的候选全被推翻后，要补一条 `needs_human` 或别的结论。

基线发现的分诊，四种去向：

| 情形 | 处理 |
|---|---|
| 测试夹具、示例文档、`.env.example` 里的假数据 | `rejected`，写明为什么是假的 |
| 真实风险 | 挂到对应控制项下判 `gap`，`source: "baseline"` |
| 依赖是真的，但实际指向境内端点（如 `openai` SDK 的 baseURL 指向 DeepSeek） | `rejected` 并引用 baseURL 所在行；若 baseURL 来自环境变量，再补一条 `needs_human` 问生产环境的实际取值 |
| 与另一条是同一件事（依赖声明 + 调用点） | 并入主记录，本条 `rejected`，reason 写「重复，已并入 F-xxx」 |

**引用密钥和个人信息时只引到它之前**。例如原文是 `const KEY = "sk-abc…"`，quote 写 `const KEY = "sk-`。合规报告自己不能泄漏数据，校验器会拦。

### 阶段 3 · 独立复核

每一条 `gap` 和 `met` 都要被**试图推翻**一次。详细协议见 [VERIFY.md](VERIFY.md)。

- 能起子 agent：交给**全新的、没看过你推理过程的** agent 去证伪。取证位置落在同一组文件里的记录可以打包给同一个复核 agent（省得重复读文件），但审计员自己不得兼任。`verifier.mode` 写 `independent`。
- 不能起子 agent：你自己重新打开每个引用的文件，按 VERIFY.md 的清单过一遍。`verifier.mode` 写 `self-recheck`（校验器会警告，报告里会如实标注）。

被推翻的改成 `rejected` 并写 `reason`，不要删。

### 阶段 4 · 过闸

把全部记录写进 `.compliance/compliance-findings.json`（格式见 [examples/compliance-findings.example.json](examples/compliance-findings.example.json)），然后运行本 skill 目录下的校验器：

```bash
node <本skill目录>/scripts/validate-findings.mjs .compliance/compliance-findings.json --root . --report .compliance/COMPLIANCE-REPORT.md
```

校验器会核对：每条引用的文件和行真的存在、quote 真的出现在那几行、报告里没有泄漏密钥或证件号、裁决纪律、14 项全覆盖。

**没通过就修到通过为止。** 报错说 quote 找不到，就回到原文重新取证——不要改 quote 去凑。报告由校验器从记录直接渲染，你不要手写或改写 `COMPLIANCE-REPORT.md`。

### 阶段 5 · 向用户汇报

用五六句话说清：

- 缺口几条，最严重的是哪一条，在哪个文件；
- 需要人回答的问题有几个，最关键的是哪个；
- 复核方式是独立还是自查；基线有没有跑成；
- 报告路径。

然后停下。不要主动开始改代码，除非用户要求。

## 边界

- 这是技术自查，**不是法律意见**。不要说「符合 XX 法」，只说「在代码中找到 / 没找到 XX 措施的证据」。
- 备案、等保定级、PIA 是主体责任，工具不能替代，只能提问。
- 法规条款编号以 `controls.json` 为准，不要凭记忆补充条款号。
- 不要把被审计项目的代码或数据发到任何外部服务。
