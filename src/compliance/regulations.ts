// src/compliance/regulations.ts — 中国 AI 合规控制项映射层
//
// 把网安法 / PIPL / 等保2.0 / 数据出境 / 生成式AI标识 等法规的「可核查控制项」
// 结构化为统一数据模型，作为合规体检引擎 (compliance/audit.ts) 的数据源。
//
// 每条控制项 = 一条真实法规条款 → 一个可被 ShellWard 检测或支撑的技术点。
// 法规出处见 README「合规」章节与研究报告（cac.gov.cn / npc.gov.cn / 国标平台）。

/** 控制项归属的法规 */
export type Regulation =
  | 'CSL'        // 《网络安全法》(2025修正, 2026-01-01 生效)
  | 'PIPL'       // 《个人信息保护法》
  | 'MLPS'       // 等级保护 2.0 (GB/T 22239-2019)
  | 'CBDT'       // 数据出境 (促进数据跨境流动规定 / 安全评估)
  | 'GENAI'      // 生成式AI暂行办法 + 标识办法 (GB 45438-2025)

/** 控制项的检测方式 —— 决定体检引擎用哪种 checker */
export type CheckMethod =
  | 'capability' // ShellWard 自身能力是否启用 (查 config.layers)
  | 'config'     // ShellWard 配置是否合规 (查 mode / threshold 等)
  | 'audit'      // 审计日志是否存在且满足留存要求
  | 'env'        // 运行环境扫描 (root / 端口 / .env 权限 / 出境端点)
  | 'manual'     // 无法自动判定，需人工确认 (主体责任，平台仅提供举证)

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface ComplianceControl {
  /** 稳定 ID，体检引擎据此映射 checker，报告据此引用 */
  id: string
  regulation: Regulation
  /** 法规条款 / 国标编号 */
  article: string
  title_zh: string
  title_en: string
  /** 监管要求原文要点 */
  requirement_zh: string
  requirement_en: string
  method: CheckMethod
  severity: Severity
  /** 不满足时的整改建议 */
  remediation_zh: string
  remediation_en: string
}

/** 法规中文显示名 */
export const REGULATION_NAMES: Record<Regulation, { zh: string; en: string }> = {
  CSL: { zh: '网络安全法 (2026.1.1)', en: 'Cybersecurity Law (2026-01-01)' },
  PIPL: { zh: '个人信息保护法', en: 'PIPL' },
  MLPS: { zh: '等保 2.0 (GB/T 22239)', en: 'MLPS 2.0' },
  CBDT: { zh: '数据出境', en: 'Cross-Border Data Transfer' },
  GENAI: { zh: '生成式AI / 内容标识', en: 'GenAI / Content Labeling' },
}

/**
 * 合规控制项清单。
 * 注：本清单帮助企业"满足"合规技术要求，不等于"替企业完成"合规
 * （备案 / 定级 / PIA 主体责任不可外包）。method='manual' 的项 ShellWard 仅提供举证支撑。
 */
export const COMPLIANCE_CONTROLS: ComplianceControl[] = [
  // ===== 网络安全法 (CSL) =====
  {
    id: 'csl-audit-log',
    regulation: 'CSL',
    article: '第二十三条',
    title_zh: '网络日志留存不少于 6 个月',
    title_en: 'Retain network logs for ≥6 months',
    requirement_zh: '采取监测、记录网络运行状态的技术措施，留存相关网络日志不少于六个月。',
    requirement_en: 'Retain network operation logs for no less than six months.',
    method: 'audit',
    severity: 'high',
    remediation_zh: '启用 ShellWard 审计日志，确保工具调用 / prompt / 决策链统一留痕、防篡改、保留 ≥6 个月。',
    remediation_en: 'Enable ShellWard audit logging with ≥6-month, tamper-resistant retention.',
  },
  {
    id: 'csl-content-block',
    regulation: 'CSL',
    article: '第四十九条',
    title_zh: '发现禁止信息立即停止传输并留痕',
    title_en: 'Stop transmission of prohibited info & keep records',
    requirement_zh: '发现法律禁止发布或传输的信息，立即停止传输、采取处置措施、保存记录并报告。',
    requirement_en: 'On detecting prohibited information, immediately stop transmission, dispose, record and report.',
    method: 'capability',
    severity: 'high',
    remediation_zh: '启用输出内容审查层 (outputScanner / outboundGuard)，对生成内容实时审查、阻断并留痕。',
    remediation_en: 'Enable output content review layers to block and log prohibited content in real time.',
  },
  {
    id: 'csl-intrusion',
    regulation: 'CSL',
    article: '第二十一条 / 等保',
    title_zh: '入侵防范与异常监测',
    title_en: 'Intrusion prevention & anomaly monitoring',
    requirement_zh: '采取防范计算机病毒和网络攻击、网络侵入等危害网络安全行为的技术措施。',
    requirement_en: 'Take technical measures against intrusion and attacks endangering network security.',
    method: 'capability',
    severity: 'medium',
    remediation_zh: '启用提示注入检测 (inputAuditor) 与危险命令拦截 (toolBlocker)。',
    remediation_en: 'Enable prompt-injection detection and dangerous-command blocking.',
  },

  // ===== 个人信息保护法 (PIPL) =====
  {
    id: 'pipl-spi-detect',
    regulation: 'PIPL',
    article: '第二十八条',
    title_zh: '敏感个人信息识别 (7类+未成年人)',
    title_en: 'Detect sensitive personal information',
    requirement_zh: '识别生物识别、医疗健康、金融账户、行踪轨迹等敏感个人信息及不满14岁未成年人信息。',
    requirement_en: 'Detect sensitive PI: biometrics, health, financial accounts, location, minors under 14.',
    method: 'capability',
    severity: 'critical',
    remediation_zh: '启用 PII/敏感数据扫描层 (outputScanner)，覆盖身份证、银行卡、手机号等中文敏感信息。',
    remediation_en: 'Enable PII/SPI scanning covering Chinese ID, bank card, phone, etc.',
  },
  {
    id: 'pipl-minimize',
    regulation: 'PIPL',
    article: '第六条 / 第十九条',
    title_zh: '最小必要 + 数据流向管控',
    title_en: 'Data minimization & flow control',
    requirement_zh: '处理个人信息应限于实现处理目的的最小范围，非必要不收集、不外发。',
    requirement_en: 'Process PI within the minimum scope necessary for the purpose.',
    method: 'capability',
    severity: 'high',
    remediation_zh: '启用数据流追踪层 (dataFlowGuard)：读取敏感数据后向外发送将被拦截。',
    remediation_en: 'Enable data-flow tracking: outbound send is blocked after sensitive data access.',
  },
  {
    id: 'pipl-pia',
    regulation: 'PIPL',
    article: '第五十五条 / 第五十六条',
    title_zh: '个人信息保护影响评估 (PIA) 并留存 ≥3 年',
    title_en: 'Conduct PIA & retain records ≥3 years',
    requirement_zh: '处理敏感PI、自动化决策、对外提供、出境等情形须事前进行 PIA，报告留存至少 3 年。',
    requirement_en: 'Conduct a PIA for sensitive PI / automated decisions / cross-border transfer; retain ≥3 years.',
    method: 'audit',
    severity: 'high',
    remediation_zh: '由数据流入/出口触发 PIA 工作流并将报告纳入防篡改审计存储（≥3 年）。',
    remediation_en: 'Trigger PIA workflow on data ingress/egress; store reports in tamper-resistant audit (≥3y).',
  },
  {
    id: 'pipl-auto-decision',
    regulation: 'PIPL',
    article: '第二十四条',
    title_zh: '自动化决策记录 + 人工复核回退',
    title_en: 'Automated-decision logging & human-in-the-loop',
    requirement_zh: '自动化决策应保证透明、结果公平，并提供拒绝纯自动化决策、要求说明的途径。',
    requirement_en: 'Ensure transparency for automated decisions and a human-review fallback.',
    method: 'capability',
    severity: 'medium',
    remediation_zh: '记录自动化决策调用（输入特征/模型版本/输出），高风险动作转人工复核 (securityGate)。',
    remediation_en: 'Log automated decisions and route high-risk actions to human review.',
  },

  // ===== 等保 2.0 (MLPS) =====
  {
    id: 'mlps-audit-fields',
    regulation: 'MLPS',
    article: 'GB/T 22239 8.1.4.3',
    title_zh: '安全审计：覆盖每用户、记录五要素',
    title_en: 'Security audit: per-user, five-element records',
    requirement_zh: '审计覆盖每个用户，记录时间、用户、类型、成败及其他相关信息，审计记录受保护防中断。',
    requirement_en: 'Audit each user; record time, user, type, result and other info; protect audit records.',
    method: 'audit',
    severity: 'high',
    remediation_zh: '使用 ShellWard 审计日志记录五要素并集中防篡改存储。',
    remediation_en: 'Use ShellWard audit log to record five elements with tamper-resistant storage.',
  },
  {
    id: 'mlps-access-control',
    regulation: 'MLPS',
    article: 'GB/T 22239 8.1.4.2',
    title_zh: '访问控制：最小权限 + 工具/数据粒度',
    title_en: 'Access control: least privilege & granularity',
    requirement_zh: '按最小权限分配，访问控制粒度达到用户/进程级及文件/数据库表级。',
    requirement_en: 'Assign least privilege; control granularity to user/process and file/table level.',
    method: 'capability',
    severity: 'medium',
    remediation_zh: '启用工具策略层 (securityGate)，对高风险工具/资源按最小授权管控。',
    remediation_en: 'Enable tool-policy gate with least-privilege control over high-risk tools.',
  },
  {
    id: 'mlps-not-root',
    regulation: 'MLPS',
    article: 'GB/T 22239 8.1.x',
    title_zh: '不以特权账户 (root) 运行',
    title_en: 'Do not run as privileged (root) account',
    requirement_zh: '应遵循最小化原则，避免以最高权限账户长期运行业务进程。',
    requirement_en: 'Follow minimization; avoid running business processes as the root account.',
    method: 'env',
    severity: 'medium',
    remediation_zh: '使用普通用户运行 + 容器隔离，避免以 root 启动 Agent。',
    remediation_en: 'Run as non-root user with container isolation.',
  },

  // ===== 数据出境 (CBDT) =====
  {
    id: 'cbdt-overseas-llm',
    regulation: 'CBDT',
    article: '促进数据跨境流动规定',
    title_zh: '境外大模型调用 = 数据出境识别',
    title_en: 'Detect overseas LLM calls as data export',
    requirement_zh: '向境外接收方提供个人信息/重要数据须识别并走相应路径；重要数据一律不得无评估出境。',
    requirement_en: 'Identify PI/important-data export to overseas recipients; important data needs assessment.',
    method: 'env',
    severity: 'critical',
    remediation_zh: '识别请求目的地是否境外大模型端点 (OpenAI/Anthropic/Gemini 等)，标记"数据出境"事件；含敏感数据应路由境内已备案模型或先脱敏。',
    remediation_en: 'Detect overseas LLM endpoints, flag data-export events; route sensitive data to domestic models or de-identify first.',
  },
  {
    id: 'cbdt-redact-before-export',
    regulation: 'CBDT',
    article: '安全评估 / 标准合同',
    title_zh: '出境前脱敏 / 防裸数据出境',
    title_en: 'De-identify before export / block raw export',
    requirement_zh: '出境数据应最小化并采取加密、去标识化等安全措施，防止敏感个人信息裸数据出境。',
    requirement_en: 'Minimize and de-identify export data; prevent raw sensitive PI from leaving the border.',
    method: 'capability',
    severity: 'high',
    remediation_zh: '启用数据流追踪 + 出境拦截：检测到敏感数据流向境外端点时阻断或脱敏。',
    remediation_en: 'Enable data-flow tracking + export interception to block or de-identify sensitive egress.',
  },

  // ===== 生成式AI / 内容标识 (GENAI) =====
  {
    id: 'genai-label',
    regulation: 'GENAI',
    article: '标识办法 / GB 45438-2025',
    title_zh: 'AI生成内容标识 (显式 + 元数据)',
    title_en: 'Label AI-generated content (explicit + metadata)',
    requirement_zh: '生成合成内容须添加用户可感知的显式标识及文件元数据隐式标识 (XMP / TC260 命名空间)。',
    requirement_en: 'Add user-visible explicit labels and metadata implicit labels (XMP / TC260 namespace).',
    method: 'manual',
    severity: 'high',
    remediation_zh: '在输出层追加"AI生成"显式标识，导出文件按 GB 45438 写入 XMP 元数据 7 字段（路线图功能）。',
    remediation_en: 'Append explicit "AI-generated" labels; write GB 45438 XMP metadata on export (roadmap).',
  },
  {
    id: 'genai-content-safety',
    regulation: 'GENAI',
    article: '暂行办法第四条 / 安全基本要求',
    title_zh: '内容安全过滤 (违禁类别 + 拒答率)',
    title_en: 'Content safety filtering (prohibited categories)',
    requirement_zh: '生成内容不得含违法不良信息；安全评估要求应拒答率 ≥95%、误拒率 ≤5%。',
    requirement_en: 'Generated content must exclude prohibited info; refusal rate ≥95%, false-refusal ≤5%.',
    method: 'manual',
    severity: 'high',
    remediation_zh: '接入内容安全过滤引擎对标 31 类违禁内容（路线图功能，可对接国产审核 API）。',
    remediation_en: 'Integrate content-safety filtering for the 31 prohibited categories (roadmap).',
  },
]

/** 按法规分组 */
export function controlsByRegulation(): Record<Regulation, ComplianceControl[]> {
  const out = {} as Record<Regulation, ComplianceControl[]>
  for (const c of COMPLIANCE_CONTROLS) {
    ;(out[c.regulation] ||= []).push(c)
  }
  return out
}
