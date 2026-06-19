// src/rules/overseas-llm.ts — 境外大模型端点识别（数据出境检测）
//
// 中国差异化能力：识别请求是否指向「境外大模型 / 境外 AI 服务」端点。
// 在中国监管下，向境外大模型 API 发送个人信息/重要数据 = 数据出境，受
// 《促进数据跨境流动规定》《数据出境安全评估办法》约束。英文工具没有
// "出境"概念，这是 ShellWard 面向中国市场的护城河之一。
//
// 用途：
//   - 体检引擎据此判断"是否存在数据出境风险"
//   - 网关层据此标记"数据出境"事件 / 触发出境前脱敏（路线图）
//
// 边界：仅做端点归属判断（不做 IP 归属解析），覆盖主流境外大模型与聚合网关。

export interface OverseasEndpoint {
  id: string
  /** 主机名匹配（小写、去端口）。命中其一即视为境外大模型端点 */
  hosts: string[]
  provider_zh: string
  provider_en: string
}

export const OVERSEAS_LLM_ENDPOINTS: OverseasEndpoint[] = [
  { id: 'openai', hosts: ['api.openai.com', 'openai.com'], provider_zh: 'OpenAI', provider_en: 'OpenAI' },
  { id: 'anthropic', hosts: ['api.anthropic.com', 'anthropic.com'], provider_zh: 'Anthropic Claude', provider_en: 'Anthropic Claude' },
  { id: 'google', hosts: ['generativelanguage.googleapis.com', 'aiplatform.googleapis.com'], provider_zh: 'Google Gemini', provider_en: 'Google Gemini' },
  { id: 'azure-openai', hosts: ['openai.azure.com'], provider_zh: 'Azure OpenAI', provider_en: 'Azure OpenAI' },
  { id: 'aws-bedrock', hosts: ['bedrock-runtime', 'bedrock.', 'amazonaws.com'], provider_zh: 'AWS Bedrock', provider_en: 'AWS Bedrock' },
  { id: 'cohere', hosts: ['api.cohere.ai', 'api.cohere.com'], provider_zh: 'Cohere', provider_en: 'Cohere' },
  { id: 'mistral', hosts: ['api.mistral.ai'], provider_zh: 'Mistral AI', provider_en: 'Mistral AI' },
  { id: 'groq', hosts: ['api.groq.com'], provider_zh: 'Groq', provider_en: 'Groq' },
  { id: 'together', hosts: ['api.together.xyz', 'api.together.ai'], provider_zh: 'Together AI', provider_en: 'Together AI' },
  { id: 'perplexity', hosts: ['api.perplexity.ai'], provider_zh: 'Perplexity', provider_en: 'Perplexity' },
  { id: 'openrouter', hosts: ['openrouter.ai'], provider_zh: 'OpenRouter (聚合网关)', provider_en: 'OpenRouter (gateway)' },
  { id: 'huggingface', hosts: ['api-inference.huggingface.co', 'huggingface.co'], provider_zh: 'HuggingFace', provider_en: 'HuggingFace' },
  { id: 'xai', hosts: ['api.x.ai'], provider_zh: 'xAI Grok', provider_en: 'xAI Grok' },
]

export interface OverseasMatch {
  isOverseas: boolean
  endpointId?: string
  provider_zh?: string
  provider_en?: string
  host?: string
}

/**
 * 从任意字符串（URL / base_url / 命令行 / 配置）中提取主机名并判断是否境外大模型端点。
 * 同时识别裸 URL 与命令行里的 https://... 形式。
 */
export function detectOverseasLLM(text: string): OverseasMatch {
  if (!text) return { isOverseas: false }
  const lower = text.toLowerCase()

  // 提取所有候选主机名：URL 中的 host，或文本中出现的端点关键字
  const hosts = extractHosts(lower)

  for (const ep of OVERSEAS_LLM_ENDPOINTS) {
    for (const h of ep.hosts) {
      // host 列表里带 '.' 或子串形式（如 'bedrock.'）做包含匹配，纯域名做后缀/相等匹配
      const hit = hosts.some(host => host === h || host.endsWith('.' + h) || host.includes(h))
        || lower.includes('://' + h)
        || lower.includes(h)
      if (hit) {
        return {
          isOverseas: true,
          endpointId: ep.id,
          provider_zh: ep.provider_zh,
          provider_en: ep.provider_en,
          host: h,
        }
      }
    }
  }
  return { isOverseas: false }
}

// ===== 境外大模型 SDK 依赖检测 =====
// 几乎每个国产 AI 项目的依赖清单里都躺着 openai/anthropic 等境外 SDK —— 这是
// 一条"数据出境通道"，命中率远高于扫 URL 字符串。英文工具不会把它框定为"出境"。

/** 包名（小写）→ 厂商 */
export const OVERSEAS_LLM_PACKAGES: Record<string, { zh: string; en: string }> = {
  // npm
  'openai': { zh: 'OpenAI', en: 'OpenAI' },
  '@anthropic-ai/sdk': { zh: 'Anthropic Claude', en: 'Anthropic Claude' },
  '@google/generative-ai': { zh: 'Google Gemini', en: 'Google Gemini' },
  '@google-cloud/aiplatform': { zh: 'Google Vertex AI', en: 'Google Vertex AI' },
  'cohere-ai': { zh: 'Cohere', en: 'Cohere' },
  '@mistralai/mistralai': { zh: 'Mistral AI', en: 'Mistral AI' },
  'groq-sdk': { zh: 'Groq', en: 'Groq' },
  '@huggingface/inference': { zh: 'HuggingFace', en: 'HuggingFace' },
  'replicate': { zh: 'Replicate', en: 'Replicate' },
  '@langchain/openai': { zh: 'OpenAI (LangChain)', en: 'OpenAI (LangChain)' },
  '@langchain/anthropic': { zh: 'Anthropic (LangChain)', en: 'Anthropic (LangChain)' },
  '@langchain/google-genai': { zh: 'Gemini (LangChain)', en: 'Gemini (LangChain)' },
  // python
  'anthropic': { zh: 'Anthropic Claude', en: 'Anthropic Claude' },
  'google-generativeai': { zh: 'Google Gemini', en: 'Google Gemini' },
  'google-cloud-aiplatform': { zh: 'Google Vertex AI', en: 'Google Vertex AI' },
  'cohere': { zh: 'Cohere', en: 'Cohere' },
  'mistralai': { zh: 'Mistral AI', en: 'Mistral AI' },
  'groq': { zh: 'Groq', en: 'Groq' },
  'together': { zh: 'Together AI', en: 'Together AI' },
  'huggingface-hub': { zh: 'HuggingFace', en: 'HuggingFace' },
  'langchain-openai': { zh: 'OpenAI (LangChain)', en: 'OpenAI (LangChain)' },
  'langchain-anthropic': { zh: 'Anthropic (LangChain)', en: 'Anthropic (LangChain)' },
  'langchain-google-genai': { zh: 'Gemini (LangChain)', en: 'Gemini (LangChain)' },
  // go
  'github.com/sashabaranov/go-openai': { zh: 'OpenAI (Go)', en: 'OpenAI (Go)' },
  'github.com/anthropics/anthropic-sdk-go': { zh: 'Anthropic (Go)', en: 'Anthropic (Go)' },
}

export interface DepMatch {
  pkg: string
  provider_zh: string
  provider_en: string
}

/** 依赖清单文件名（小写）判定 */
export function isDependencyManifest(filename: string): boolean {
  const f = filename.toLowerCase()
  return f === 'package.json' || f === 'requirements.txt' || f === 'pyproject.toml' || f === 'go.mod'
}

/**
 * 从依赖清单内容中提取境外大模型 SDK 依赖。
 * 对 package.json 解析 JSON 的 deps/devDeps/peerDeps；其余按"出现包名"宽松匹配。
 */
export function detectOverseasDeps(filename: string, content: string): DepMatch[] {
  const f = filename.toLowerCase()
  const names = new Set<string>()

  if (f === 'package.json') {
    try {
      const json = JSON.parse(content)
      for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
        const deps = json[field]
        if (deps && typeof deps === 'object') {
          for (const k of Object.keys(deps)) names.add(k.toLowerCase())
        }
      }
    } catch { /* 解析失败则跳过 */ }
  } else {
    // requirements.txt / pyproject.toml / go.mod：按行宽松提取包名 token
    for (const raw of content.split('\n')) {
      const line = raw.trim().toLowerCase()
      if (!line || line.startsWith('#') || line.startsWith('//')) continue
      // 提取依赖名：requirements `pkg==x` / pyproject `"pkg>=x"` / go.mod `module vX`
      const tokens = line.match(/[a-z0-9_.\-\/@]+/g) || []
      for (const t of tokens) names.add(t)
    }
  }

  const matches: DepMatch[] = []
  const seen = new Set<string>()
  for (const [pkg, prov] of Object.entries(OVERSEAS_LLM_PACKAGES)) {
    if (names.has(pkg.toLowerCase()) && !seen.has(pkg)) {
      seen.add(pkg)
      matches.push({ pkg, provider_zh: prov.zh, provider_en: prov.en })
    }
  }
  return matches
}

/** 从文本中粗提取主机名（URL host 段） */
function extractHosts(lowerText: string): string[] {
  const hosts: string[] = []
  const urlRe = /https?:\/\/([a-z0-9.\-]+)(?::\d+)?/g
  let m: RegExpExecArray | null
  while ((m = urlRe.exec(lowerText)) !== null) {
    hosts.push(m[1])
  }
  return hosts
}
