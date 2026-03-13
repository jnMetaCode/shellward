// src/index.ts — ShellWard plugin entry point (v0.4.0)
// 8 defense layers + 6 slash commands + 1 security skill

import { AuditLog } from './audit-log'
import { setupPromptGuard } from './layers/prompt-guard'
import { setupOutputScanner } from './layers/output-scanner'
import { setupToolBlocker } from './layers/tool-blocker'
import { setupInputAuditor } from './layers/input-auditor'
import { setupSecurityGate } from './layers/security-gate'
import { setupOutboundGuard } from './layers/outbound-guard'
import { setupDataFlowGuard } from './layers/data-flow-guard'
import { setupSessionGuard } from './layers/session-guard'
import { registerAllCommands } from './commands/index'
import { DEFAULT_CONFIG, resolveLocale } from './types'
import { checkForUpdate } from './update-check'
import type { ShellWardConfig } from './types'

const CURRENT_VERSION = '0.4.0'

/**
 * Wrap api.on so every hook handler gets try-catch protection.
 * If a security hook throws, we log the error and fail-safe:
 * - before_tool_call: block (deny on error, safer than allow)
 * - other hooks: return undefined (don't break the chain)
 */
function createSafeApi(api: any, log: AuditLog): any {
  return {
    ...api,
    on(hookName: string, handler: Function, opts?: any) {
      const isBlockHook = hookName === 'before_tool_call'
      const wrappedHandler = (event: any) => {
        try {
          return handler(event)
        } catch (err: any) {
          const msg = err?.message || String(err)
          log.write({
            level: 'CRITICAL',
            layer: 'L0',
            action: 'error',
            detail: `Hook ${opts?.name || hookName} threw: ${msg.slice(0, 200)}`,
          })
          try { api.logger.warn(`[ShellWard] Hook error in ${opts?.name || hookName}: ${msg}`) } catch {}
          // Fail-safe: block on security hooks, pass on others
          if (isBlockHook) {
            return { block: true, blockReason: `⚠️ [ShellWard] Internal error in security check — operation blocked for safety` }
          }
          return undefined
        }
      }
      api.on(hookName, wrappedHandler, opts)
    },
  }
}

function mergeConfig(userConfig: Partial<ShellWardConfig> | undefined): ShellWardConfig {
  if (!userConfig) return { ...DEFAULT_CONFIG }

  // Validate mode
  const mode = userConfig.mode === 'audit' ? 'audit' : 'enforce'

  // Validate locale
  const validLocales = ['auto', 'zh', 'en'] as const
  const locale = validLocales.includes(userConfig.locale as any)
    ? (userConfig.locale as typeof validLocales[number])
    : DEFAULT_CONFIG.locale

  // Validate injectionThreshold: clamp to 0-100
  let threshold = userConfig.injectionThreshold ?? DEFAULT_CONFIG.injectionThreshold
  threshold = Math.max(0, Math.min(100, Math.round(threshold)))

  return {
    mode,
    locale,
    injectionThreshold: threshold,
    layers: {
      ...DEFAULT_CONFIG.layers,
      ...(userConfig.layers || {}),
    },
  }
}

export default {
  id: 'shellward',

  register(api: any) {
    const config = mergeConfig(api.config)
    const log = new AuditLog(config)
    const enforce = config.mode === 'enforce'
    const locale = resolveLocale(config)
    const safe = createSafeApi(api, log)

    const startMsg = locale === 'zh'
      ? `[ShellWard] 首个中文 OpenClaw 安全插件已启动 (v${CURRENT_VERSION}, 模式: ${config.mode})`
      : `[ShellWard] Security plugin started (v${CURRENT_VERSION}, mode: ${config.mode})`
    api.logger.info(startMsg)

    // === Defense Layers (L1-L8) ===
    // All layers use `safe` wrapper — hooks get automatic try-catch + fail-safe

    // L1: Prompt Guard (before_prompt_build — prependSystemContext for caching)
    if (config.layers.promptGuard) {
      setupPromptGuard(safe, config, log)
    }

    // L2: Output Scanner (tool_result_persist — redact PII in tool results)
    if (config.layers.outputScanner) {
      setupOutputScanner(safe, config, log, enforce)
    }

    // L3: Tool Blocker (before_tool_call — block dangerous commands/paths)
    if (config.layers.toolBlocker) {
      setupToolBlocker(safe, config, log, enforce)
    }

    // L4: Input Auditor (before_tool_call + message_received — injection detection)
    if (config.layers.inputAuditor) {
      setupInputAuditor(safe, config, log, enforce)
    }

    // L5: Security Gate (registerTool — defense in depth, uses raw api for registerTool)
    if (config.layers.securityGate) {
      setupSecurityGate(api, config, log, enforce)
    }

    // L6: Outbound Guard (message_sending — redact PII in LLM responses + canary detection)
    if (config.layers.outboundGuard) {
      setupOutboundGuard(safe, config, log, enforce)
    }

    // L7: Data Flow Guard (after_tool_call + before_tool_call — anti-exfiltration)
    if (config.layers.dataFlowGuard) {
      setupDataFlowGuard(safe, config, log, enforce)
    }

    // L8: Session Guard (session_end + subagent_spawning — lifecycle security)
    if (config.layers.sessionGuard) {
      setupSessionGuard(safe, config, log, enforce)
    }

    // === Slash Commands ===
    if (api.registerCommand) {
      registerAllCommands(api, config)
      api.logger.info('[ShellWard] 6 commands registered: /security /audit /harden /scan-plugins /check-updates /cg')
    }

    // Count enabled layers
    const allLayers = ['promptGuard', 'outputScanner', 'toolBlocker', 'inputAuditor', 'securityGate', 'outboundGuard', 'dataFlowGuard', 'sessionGuard']
    const enabledCount = allLayers.filter(k => (config.layers as any)[k]).length

    const layerMsg = locale === 'zh'
      ? `[ShellWard] ${enabledCount} 层防御已激活 — 身份证/手机/银行卡脱敏 | 注入检测 | 外泄拦截`
      : `[ShellWard] ${enabledCount} defense layers active`
    api.logger.info(layerMsg)

    log.write({
      level: 'INFO',
      layer: 'L1',
      action: 'allow',
      detail: `ShellWard v${CURRENT_VERSION} started with ${enabledCount} layers`,
    })

    // === Non-blocking update check (async, won't delay startup) ===
    // Only notifies ONCE per new version — won't repeat after user has seen it
    checkForUpdate(CURRENT_VERSION).then(result => {
      if (result?.shouldNotify) {
        const msg = locale === 'zh'
          ? `[ShellWard] 新版本 v${result.latest} 可用 (当前 v${result.current})。运行 \`openclaw plugins update shellward\` 更新`
          : `[ShellWard] Update available: v${result.latest} (current v${result.current}). Run \`openclaw plugins update shellward\` to update`
        api.logger.warn(msg)
      }
    }).catch(() => { /* silently ignore network errors */ })
  },
}
