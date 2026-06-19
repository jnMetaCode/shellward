// src/rules/domestic-alternatives.ts — 境内已备案大模型替代建议
//
// 扫到境外大模型（端点/SDK 依赖）后，给出可执行的「境内合规替代」处方：
// 把"你有数据出境风险"变成"换成这个、这样换"。这是 ShellWard 面向中国
// 市场最具差异化、最可执行的一环 —— 英文工具不会做。
//
// 杀手锏：境内主流模型多数提供 **OpenAI 兼容接口**，对 `openai` SDK 的项目
// 往往只需改 base_url + api key、代码零改动即可迁移到合规模型。
//
// 注：base_url 为各厂商公开的 OpenAI 兼容端点（可能随官方调整，迁移前以官方文档为准）。

export interface DomesticModel {
  id: string
  name_zh: string
  name_en: string
  vendor_zh: string
  /** OpenAI 兼容 base_url（若支持） */
  baseUrl: string
  /** 是否提供 OpenAI 兼容接口（决定迁移难度） */
  openaiCompatible: boolean
}

/** 境内主流大模型（均为境内可备案/合规部署，按知名度排序） */
export const DOMESTIC_MODELS: DomesticModel[] = [
  {
    id: 'qwen', name_zh: '通义千问', name_en: 'Qwen', vendor_zh: '阿里云百炼/DashScope',
    baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', openaiCompatible: true,
  },
  {
    id: 'deepseek', name_zh: 'DeepSeek', name_en: 'DeepSeek', vendor_zh: '深度求索',
    baseUrl: 'https://api.deepseek.com', openaiCompatible: true,
  },
  {
    id: 'kimi', name_zh: 'Kimi', name_en: 'Kimi (Moonshot)', vendor_zh: '月之暗面',
    baseUrl: 'https://api.moonshot.cn/v1', openaiCompatible: true,
  },
  {
    id: 'glm', name_zh: '智谱 GLM', name_en: 'Zhipu GLM', vendor_zh: '智谱 AI',
    baseUrl: 'https://open.bigmodel.cn/api/paas/v4', openaiCompatible: true,
  },
  {
    id: 'doubao', name_zh: '豆包', name_en: 'Doubao', vendor_zh: '字节火山方舟',
    baseUrl: 'https://ark.cn-beijing.volces.com/api/v3', openaiCompatible: true,
  },
  {
    id: 'ernie', name_zh: '文心一言', name_en: 'ERNIE', vendor_zh: '百度千帆',
    baseUrl: 'https://qianfan.baidubce.com/v2', openaiCompatible: true,
  },
]

export interface DomesticSuggestion {
  /** 触发的境外厂商（中文） */
  overseas_zh: string
  overseas_en: string
  /** 迁移难度 */
  difficulty_zh: string
  difficulty_en: string
  /** 推荐的境内替代（取兼容优先的前几个） */
  alternatives: DomesticModel[]
}

// 哪些境外厂商走 OpenAI 兼容协议（其 SDK 项目可零代码迁移到境内兼容端点）
const OPENAI_PROTOCOL = new Set(['openai', 'azure-openai', 'groq', 'together', 'mistral', 'perplexity', 'openrouter', 'xai'])

/**
 * 针对某个境外厂商给出境内替代建议。
 * @param key endpointId（如 'openai'）或 provider_en（如 'OpenAI'）
 */
export function suggestDomestic(key: string, provider_zh?: string, provider_en?: string): DomesticSuggestion {
  const k = key.toLowerCase()
  const isOpenAiProtocol = OPENAI_PROTOCOL.has(k) || /openai/.test(k)

  // 推荐：OpenAI 兼容的境内模型优先（迁移最省事）
  const alternatives = DOMESTIC_MODELS.filter(m => m.openaiCompatible).slice(0, 4)

  const difficulty_zh = isOpenAiProtocol
    ? '低 — 多为 OpenAI 兼容协议，通常只需改 base_url + API key，代码零改动'
    : '中 — SDK 不同，建议改用境内模型的 OpenAI 兼容端点并调整调用代码'
  const difficulty_en = isOpenAiProtocol
    ? 'Low — OpenAI-compatible; usually just swap base_url + API key, no code change'
    : 'Medium — different SDK; switch to a domestic OpenAI-compatible endpoint and adjust calls'

  return {
    overseas_zh: provider_zh || key,
    overseas_en: provider_en || key,
    difficulty_zh,
    difficulty_en,
    alternatives,
  }
}
