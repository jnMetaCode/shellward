// 示例：一个有典型合规缺口的客服机器人（仅供 skill 演示与测试，非真实项目）
import OpenAI from 'openai'
import { findUser } from './db'
import { log } from './logger'

const client = new OpenAI({ baseURL: 'https://api.openai.com/v1', apiKey: process.env.LLM_KEY })

export async function reply(userId: string, question: string) {
  const user = await findUser(userId)
  const context = `客户姓名 ${user.name}，手机 ${user.phone}，身份证 ${user.idCard}`
  const r = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: context },
      { role: 'user', content: question },
    ],
  })
  log('reply', question)
  return r.choices[0].message.content
}
