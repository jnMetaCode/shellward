// src/audit-log.ts — JSONL audit log, zero dependencies

import { appendFileSync, mkdirSync, renameSync, statSync, writeFileSync } from 'fs'
import { join } from 'path'
import { getHomeDir } from './utils.js'
import type { AuditEntry, ShellWardConfig } from './types.js'

const LOG_DIR = join(getHomeDir(), '.openclaw', 'shellward')
const LOG_FILE = join(LOG_DIR, 'audit.jsonl')
const MAX_SIZE_BYTES = 100 * 1024 * 1024 // 100 MB

const RISK_SCORES: Record<string, number> = {
  CRITICAL: 10,
  HIGH: 7,
  MEDIUM: 4,
  LOW: 2,
  INFO: 0,
}

export class AuditLog {
  private config: ShellWardConfig
  private rotating = false

  constructor(config: ShellWardConfig) {
    this.config = config
    try {
      mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 })
      // Ensure log file exists with restricted permissions (owner-only)
      try {
        statSync(LOG_FILE)
      } catch {
        writeFileSync(LOG_FILE, '', { mode: 0o600 })
      }
    } catch { /* directory may already exist */ }
  }

  write(entry: Pick<AuditEntry, 'level' | 'layer' | 'action' | 'detail'> & Record<string, unknown>): void {
    try {
      const record: AuditEntry = {
        ...entry,
        level: entry.level,
        layer: entry.layer,
        action: entry.action,
        detail: entry.detail,
        ts: new Date().toISOString(),
        mode: this.config.mode,
        riskScore: RISK_SCORES[entry.level] ?? 0,
      }
      appendFileSync(LOG_FILE, JSON.stringify(record) + '\n', { mode: 0o600 })
      this.rotateIfNeeded()
    } catch (e: any) {
      // Log failure must not break plugin, but warn via stderr
      try { process.stderr.write(`[ShellWard] audit log write failed: ${e?.message}\n`) } catch {}
    }
  }

  private rotateIfNeeded(): void {
    if (this.rotating) return
    try {
      const stat = statSync(LOG_FILE)
      if (stat.size > MAX_SIZE_BYTES) {
        this.rotating = true
        const ts = new Date().toISOString().replace(/[:.]/g, '-')
        renameSync(LOG_FILE, `${LOG_FILE}.${ts}.bak`)
        writeFileSync(LOG_FILE, '', { mode: 0o600 })
      }
    } catch { /* ignore */ } finally {
      this.rotating = false
    }
  }
}
