// src/audit-log.ts — JSONL audit log, zero dependencies

import { appendFileSync, mkdirSync, renameSync, statSync } from 'fs'
import { join } from 'path'
import type { AuditEntry, ClawGuardConfig } from './types'

const LOG_DIR = join(process.env.HOME || '~', '.openclaw', 'clawguard')
const LOG_FILE = join(LOG_DIR, 'audit.jsonl')
const MAX_SIZE_BYTES = 100 * 1024 * 1024 // 100 MB

export class AuditLog {
  private config: ClawGuardConfig

  constructor(config: ClawGuardConfig) {
    this.config = config
    try {
      mkdirSync(LOG_DIR, { recursive: true })
    } catch { /* directory may already exist */ }
  }

  write(entry: Omit<AuditEntry, 'ts' | 'mode'>): void {
    try {
      const record: AuditEntry = {
        ts: new Date().toISOString(),
        mode: this.config.mode,
        ...entry,
      }
      appendFileSync(LOG_FILE, JSON.stringify(record) + '\n')
      this.rotateIfNeeded()
    } catch { /* log failure must not break plugin */ }
  }

  private rotateIfNeeded(): void {
    try {
      const stat = statSync(LOG_FILE)
      if (stat.size > MAX_SIZE_BYTES) {
        renameSync(LOG_FILE, LOG_FILE + '.' + Date.now() + '.bak')
      }
    } catch { /* ignore */ }
  }
}
