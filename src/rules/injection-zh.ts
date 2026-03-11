// src/rules/injection-zh.ts — Chinese prompt injection detection rules

import type { InjectionRule } from '../types'

export const INJECTION_RULES_ZH: InjectionRule[] = [
  {
    id: 'zh_ignore_prev',
    name: '忽略之前指令',
    pattern: '(?:请|你要|现在)?忽略(?:之前|上面|以上|前面|所有)(?:的)?(?:指令|指示|规则|提示|要求|约束)',
    riskScore: 40,
    category: 'override',
  },
  {
    id: 'zh_new_role',
    name: '角色扮演攻击',
    pattern: '(?:你现在是|你的新身份是|从现在起你是|假装你是|扮演|你是一个)(?:.*?)(?:助手|AI|机器人|黑客|专家)',
    riskScore: 35,
    category: 'role_hijack',
  },
  {
    id: 'zh_system_prompt',
    name: '系统提示窃取',
    pattern: '(?:输出|显示|打印|告诉我|重复|泄露|展示)(?:你的)?(?:系统|初始|原始)?(?:提示词|system\\s*prompt|指令|规则|约束)',
    riskScore: 30,
    category: 'exfiltration',
  },
  {
    id: 'zh_developer_mode',
    name: '开发者模式',
    pattern: '(?:进入|启用|开启|切换到)(?:开发者|调试|测试|管理员|root|超级)(?:模式|权限)',
    riskScore: 35,
    category: 'privilege_escalation',
  },
  {
    id: 'zh_no_restriction',
    name: '解除限制',
    pattern: '(?:取消|移除|去掉|关闭|忽略|跳过|绕过)(?:所有|一切|你的)?(?:限制|约束|安全|过滤|审查|规则)',
    riskScore: 40,
    category: 'override',
  },
  {
    id: 'zh_do_not_refuse',
    name: '禁止拒绝',
    pattern: '(?:不要|不许|不能|不可以|禁止你)(?:拒绝|拒绝回答|说不|推辞)',
    riskScore: 25,
    category: 'override',
  },
  {
    id: 'zh_hidden_instruction',
    name: '隐藏指令标记',
    pattern: '(?:以下是|下面是)?(?:隐藏|秘密|真正的|实际的)(?:指令|命令|提示|任务)',
    riskScore: 35,
    category: 'injection',
  },
  {
    id: 'zh_output_format_hijack',
    name: '输出格式劫持',
    pattern: '(?:只|仅|必须)?(?:输出|回复|返回|回答)(?:以下|如下|这个)(?:内容|文字|文本)',
    riskScore: 15,
    category: 'hijack',
  },
  {
    id: 'zh_data_exfil',
    name: '数据外泄',
    pattern: '(?:把|将)(?:所有|全部)?(?:对话|聊天|消息|记录|历史|数据|文件)(?:发送|传输|上传|转发)(?:到|给)',
    riskScore: 40,
    category: 'exfiltration',
  },
  {
    id: 'zh_boundary_marker',
    name: '边界标记注入',
    pattern: '(?:<<|\\[\\[|\\{\\{)\\s*(?:SYSTEM|系统|SYS|END|新指令|NEW)\\s*(?:>>|\\]\\]|\\}\\})',
    riskScore: 30,
    category: 'injection',
  },
  {
    id: 'zh_act_as',
    name: '行为替换',
    pattern: '(?:请以|用|按照|模仿)(?:.*?)(?:的方式|的口吻|的风格|的身份)(?:回答|回复|说话|输出)',
    riskScore: 20,
    category: 'role_hijack',
  },
  {
    id: 'zh_jailbreak',
    name: '越狱关键词',
    pattern: '(?:DAN|越狱|jailbreak|无限制模式|do\\s*anything\\s*now)',
    flags: 'i',
    riskScore: 40,
    category: 'jailbreak',
  },
]
