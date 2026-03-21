// src/rules/dangerous-commands.ts — Shell command blocklist (bilingual)

import type { DangerousCommandRule } from '../types.js'

export const DANGEROUS_COMMANDS: DangerousCommandRule[] = [
  {
    id: 'rm_rf_root',
    pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+-[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*\s+-[a-zA-Z]*r|-[a-zA-Z]*rf[a-zA-Z]*)\s+[\/~]/i,
    description_zh: '递归强制删除根目录或用户目录',
    description_en: 'Recursive force delete on root or home directory',
  },
  {
    id: 'rm_rf_wildcard',
    pattern: /rm\s+(-[a-zA-Z]*rf|-[a-zA-Z]*fr)\s+\*/i,
    description_zh: '递归强制删除通配符匹配的所有文件',
    description_en: 'Recursive force delete with wildcard',
  },
  {
    id: 'mkfs',
    pattern: /mkfs\b/i,
    description_zh: '格式化磁盘',
    description_en: 'Format disk partition',
  },
  {
    id: 'dd_if',
    pattern: /dd\s+if=/i,
    description_zh: '低级磁盘操作（可能覆盖磁盘数据）',
    description_en: 'Low-level disk operation (may overwrite data)',
  },
  {
    id: 'curl_pipe_sh',
    pattern: /curl\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh/i,
    description_zh: '从网络下载并直接执行脚本',
    description_en: 'Download and pipe to shell execution',
  },
  {
    id: 'wget_pipe_sh',
    pattern: /wget\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh/i,
    description_zh: '从网络下载并直接执行脚本',
    description_en: 'Download and pipe to shell execution',
  },
  {
    id: 'dev_write',
    pattern: />\s*\/dev\/[sh]d[a-z]/i,
    description_zh: '直接写入磁盘设备',
    description_en: 'Direct write to disk device',
  },
  {
    id: 'chmod_777',
    pattern: /chmod\s+(-[a-zA-Z]*\s+)?777(?:\s|$)/i,
    description_zh: '设置全局可读写可执行权限',
    description_en: 'Set world-readable/writable/executable permissions',
  },
  {
    id: 'kill_all',
    pattern: /killall\s+-9|kill\s+-9\s+-1/i,
    description_zh: '强制终止所有进程',
    description_en: 'Force kill all processes',
  },
  {
    id: 'iptables_flush',
    pattern: /iptables\s+-F/i,
    description_zh: '清空防火墙规则',
    description_en: 'Flush all firewall rules',
  },
  {
    id: 'history_clear',
    pattern: /history\s+-c|>\s*~\/\.bash_history|>\s*~\/\.zsh_history/i,
    description_zh: '清除命令历史（可能是攻击后清痕迹）',
    description_en: 'Clear command history (potential post-attack cleanup)',
  },
  {
    id: 'fork_bomb',
    pattern: /:\(\)\s*\{\s*:\|:&\s*\}\s*;?|\.\/[a-z]+\s*&\s*\.\/[a-z]+/i,
    description_zh: 'Fork 炸弹（耗尽系统资源）',
    description_en: 'Fork bomb (exhaust system resources)',
  },
  {
    id: 'eval_base64',
    pattern: /eval\s+.*(?:base64|atob)|base64\s+-d.*\|\s*(?:ba)?sh/i,
    description_zh: 'Base64 解码后执行（混淆攻击）',
    description_en: 'Base64 decode and execute (obfuscated attack)',
  },
  {
    id: 'reverse_shell',
    pattern: /\/dev\/tcp\/|nc\s+-[a-zA-Z]*e\s|ncat\s.*-e\s|bash\s+-i\s+>&\s*\/dev/i,
    description_zh: '反弹 Shell（远程控制）',
    description_en: 'Reverse shell (remote control)',
  },
  {
    id: 'crontab_overwrite',
    pattern: /crontab\s+-r|echo\s+.*>\s*\/var\/spool\/cron/i,
    description_zh: '覆盖或删除定时任务',
    description_en: 'Overwrite or remove crontab entries',
  },
  {
    id: 'nc_exfil',
    pattern: /\|\s*(?:nc|ncat|netcat)\s+\S+\s+\d+/i,
    description_zh: '通过 netcat 向远程主机传输数据',
    description_en: 'Pipe data to remote host via netcat',
  },
  {
    id: 'crontab_append',
    pattern: />>\s*(?:\/etc\/crontab|\/var\/spool\/cron)/i,
    description_zh: '追加定时任务（可能植入后门）',
    description_en: 'Append to crontab (potential backdoor)',
  },
]

/**
 * Normalize command string before pattern matching:
 * - Split on command separators (;, &&, ||, \n) and check each part
 * - Trim whitespace
 */
export function splitCommands(cmd: string): string[] {
  return cmd.split(/\s*(?:;|&&|\|\||[\r\n]+)\s*/).filter(Boolean)
}
