// src/index.ts — ShellWard: AI Agent Security Middleware
//
// Two usage modes:
//   1. SDK (any platform):  import { ShellWard } from 'shellward'
//   2. OpenClaw plugin:     import shellward from 'shellward'
//
// See docs/定位.md — ShellWard is an AI Agent Security Layer,
// NOT just an OpenClaw plugin. The core engine is platform-agnostic.

import { ShellWard } from './core/engine'
import { setupPromptGuard } from './layers/prompt-guard'
import { setupOutputScanner } from './layers/output-scanner'
import { setupToolBlocker } from './layers/tool-blocker'
import { setupInputAuditor } from './layers/input-auditor'
import { setupSecurityGate } from './layers/security-gate'
import { setupOutboundGuard } from './layers/outbound-guard'
import { setupDataFlowGuard } from './layers/data-flow-guard'
import { setupSessionGuard } from './layers/session-guard'
import { registerAllCommands } from './commands/index'
import { checkForUpdate } from './update-check'
import { runAutoCheckOnStartup } from './auto-check'

const CURRENT_VERSION = '0.5.10'

// Re-export core engine for SDK usage
export { ShellWard } from './core/engine'
export type { CheckResult, ScanResult, InjectionResult, ResponseCheckResult } from './core/engine'
export type { ShellWardConfig } from './types'

/**
 * Wrap api.on so every hook handler gets try-catch protection.
 * If a security hook throws, we log the error and fail-safe:
 * - before_tool_call: block (deny on error, safer than allow)
 * - other hooks: return undefined (don't break the chain)
 *
 * Returns boolean indicating whether hook registration succeeded.
 * This allows layers to detect missing hooks and register fallbacks.
 */
function createSafeApi(api: any, guard: ShellWard): any {
  return {
    ...api,
    on(hookName: string, handler: Function, opts?: any): boolean {
      const isBlockHook = hookName === 'before_tool_call'
      const wrappedHandler = (event: any) => {
        try {
          return handler(event)
        } catch (err: any) {
          const msg = err?.message || String(err)
          guard.log.write({
            level: 'CRITICAL',
            layer: 'L0',
            action: 'error',
            detail: `Hook ${opts?.name || hookName} threw: ${msg.slice(0, 200)}`,
          })
          try { api.logger.warn(`[ShellWard] Hook error in ${opts?.name || hookName}: ${msg}`) } catch {}
          if (isBlockHook) {
            return { block: true, blockReason: `⚠️ [ShellWard] Internal error in security check — operation blocked for safety` }
          }
          return undefined
        }
      }
      try {
        api.on(hookName, wrappedHandler, opts)
        return true
      } catch {
        return false
      }
    },
  }
}

// OpenClaw plugin entry point
export default {
  id: 'shellward',

  register(api: any) {
    const guard = new ShellWard(api.config)
    const enforce = guard.config.mode === 'enforce'
    const safe = createSafeApi(api, guard)

    const startMsg = guard.locale === 'zh'
      ? `[ShellWard] AI Agent 安全中间件已启动 (v${CURRENT_VERSION}, 模式: ${guard.config.mode})`
      : `[ShellWard] AI Agent Security Middleware started (v${CURRENT_VERSION}, mode: ${guard.config.mode})`
    api.logger.info(startMsg)

    // === Defense Layers (L1-L8) — thin adapters calling core engine ===

    if (guard.config.layers.promptGuard) {
      setupPromptGuard(safe, guard)
    }

    if (guard.config.layers.outputScanner) {
      setupOutputScanner(safe, guard)
    }

    if (guard.config.layers.toolBlocker) {
      setupToolBlocker(safe, guard, enforce)
    }

    if (guard.config.layers.inputAuditor) {
      setupInputAuditor(safe, guard, enforce)
    }

    // L5 uses raw api for registerTool (not a hook)
    if (guard.config.layers.securityGate) {
      setupSecurityGate(api, guard, enforce)
    }

    if (guard.config.layers.outboundGuard) {
      setupOutboundGuard(safe, guard, enforce)
    }

    if (guard.config.layers.dataFlowGuard) {
      setupDataFlowGuard(safe, guard, enforce)
    }

    if (guard.config.layers.sessionGuard) {
      setupSessionGuard(safe, guard, enforce)
    }

    // === Slash Commands ===
    if (api.registerCommand) {
      registerAllCommands(api, guard.config)
      api.logger.info('[ShellWard] 6 commands registered')
    }

    const allLayers = ['promptGuard', 'outputScanner', 'toolBlocker', 'inputAuditor', 'securityGate', 'outboundGuard', 'dataFlowGuard', 'sessionGuard']
    const enabledCount = allLayers.filter(k => (guard.config.layers as any)[k]).length

    const layerMsg = guard.locale === 'zh'
      ? `[ShellWard] ${enabledCount} 层防御已激活 — 敏感数据审计 | 注入检测 | 外泄拦截`
      : `[ShellWard] ${enabledCount} defense layers active`
    api.logger.info(layerMsg)

    guard.log.write({
      level: 'INFO',
      layer: 'L1',
      action: 'allow',
      detail: `ShellWard v${CURRENT_VERSION} started with ${enabledCount} layers`,
    })

    checkForUpdate(CURRENT_VERSION).then(result => {
      if (result?.shouldNotify) {
        const msg = guard.locale === 'zh'
          ? `[ShellWard] 新版本 v${result.latest} 可用 (当前 v${result.current})`
          : `[ShellWard] Update available: v${result.latest} (current v${result.current})`
        api.logger.warn(msg)
      }
    }).catch(() => {})

    // 启动时自动安全检查（OpenClaw 漏洞、插件风险、MCP 配置、root 运行）
    if (guard.config.autoCheckOnStartup !== false) {
      runAutoCheckOnStartup(api.logger, guard.locale)
    }
  },
}
