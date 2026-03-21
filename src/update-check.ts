// src/update-check.ts — Non-blocking version check + remote vulnerability DB
// Uses only Node.js built-in https module (zero dependencies)
//
// Anti-annoyance design:
// - Network check at most once per 24 hours
// - Same version update only notified ONCE (dismissed = silenced until next version)
// - Vuln DB cached 24h, /check-updates always shows latest cache
// - All network failures are silent and cached to avoid repeated timeouts

import { get } from 'https'
import { mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { getHomeDir } from './utils.js'

const CACHE_DIR = join(getHomeDir(), '.openclaw', 'shellward')
const CACHE_FILE = join(CACHE_DIR, 'update-cache.json')
const VULN_CACHE_FILE = join(CACHE_DIR, 'vuln-db-cache.json')
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000 // 24 hours

// Remote sources
const NPM_REGISTRY_URL = 'https://registry.npmjs.org/shellward/latest'
const VULN_DB_URL = 'https://raw.githubusercontent.com/jnMetaCode/shellward/main/vuln-db.json'

interface UpdateCache {
  lastCheck: number
  latestVersion: string | null
  notifiedVersion: string | null  // version user was already notified about — won't repeat
}

export interface VulnEntry {
  affectedBelow: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  id: string
  ghsa?: string
  description_zh: string
  description_en: string
}

export interface SupplyChainAlert {
  id: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  date: string
  description_zh: string
  description_en: string
}

/**
 * Simple HTTPS GET with redirect support. Timeout: 5s.
 */
function httpsGet(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = get(url, { timeout: 5000 }, (res) => {
      if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
        get(res.headers.location, { timeout: 5000 }, (res2) => {
          let data = ''
          res2.on('data', (chunk: Buffer) => { data += chunk.toString() })
          res2.on('end', () => resolve(data))
          res2.on('error', reject)
        }).on('error', reject)
        return
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`))
        return
      }
      let data = ''
      res.on('data', (chunk: Buffer) => { data += chunk.toString() })
      res.on('end', () => resolve(data))
      res.on('error', reject)
    })
    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')) })
  })
}

/**
 * Check npm for latest version.
 *
 * Returns result with `shouldNotify`:
 * - true = first time seeing this new version, show the message
 * - false = already notified for this version, stay quiet
 * Returns null if check skipped or failed.
 */
export async function checkForUpdate(currentVersion: string): Promise<{
  current: string
  latest: string
  updateAvailable: boolean
  shouldNotify: boolean
} | null> {
  try {
    const cache = readCache<UpdateCache>(CACHE_FILE)

    // Use cached version if within interval
    let latest: string | null = null
    if (cache && Date.now() - cache.lastCheck < CHECK_INTERVAL_MS && cache.latestVersion) {
      latest = cache.latestVersion
    } else {
      // Fetch from npm
      const body = await httpsGet(NPM_REGISTRY_URL)
      const data = JSON.parse(body)
      latest = data.version
      if (!latest || typeof latest !== 'string') return null

      // Save to cache (preserve notifiedVersion)
      writeCache(CACHE_FILE, {
        lastCheck: Date.now(),
        latestVersion: latest,
        notifiedVersion: cache?.notifiedVersion || null,
      })
    }

    const updateAvailable = compareVersions(latest, currentVersion) > 0

    // Determine if we should notify:
    // Only notify if update available AND we haven't already notified for this exact version
    const alreadyNotified = cache?.notifiedVersion === latest
    const shouldNotify = updateAvailable && !alreadyNotified

    // If we're going to notify, mark it so we don't repeat
    if (shouldNotify) {
      const freshCache = readCache<UpdateCache>(CACHE_FILE) || { lastCheck: Date.now(), latestVersion: latest, notifiedVersion: null }
      freshCache.notifiedVersion = latest
      writeCache(CACHE_FILE, freshCache)
    }

    return { current: currentVersion, latest, updateAvailable, shouldNotify }
  } catch {
    return null
  }
}

/**
 * Fetch remote vulnerability database. Cached 24h. Local fallback on failure.
 */
export async function fetchVulnDB(): Promise<{ vulns: VulnEntry[]; alerts: SupplyChainAlert[] }> {
  try {
    const cached = readCache<{ lastCheck: number; vulns: VulnEntry[]; alerts: SupplyChainAlert[] }>(VULN_CACHE_FILE)
    if (cached && Date.now() - cached.lastCheck < CHECK_INTERVAL_MS && cached.vulns) {
      return { vulns: cached.vulns, alerts: cached.alerts || [] }
    }

    const body = await httpsGet(VULN_DB_URL)
    const data = JSON.parse(body)
    const vulns: VulnEntry[] = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : []
    const alerts: SupplyChainAlert[] = Array.isArray(data.supplyChainAlerts) ? data.supplyChainAlerts : []

    writeCache(VULN_CACHE_FILE, { lastCheck: Date.now(), vulns, alerts })
    return { vulns, alerts }
  } catch {
    // Cache failure result to avoid repeated timeouts
    const cached = readCache<{ vulns: VulnEntry[]; alerts: SupplyChainAlert[] }>(VULN_CACHE_FILE)
    const fallback = { vulns: cached?.vulns || [], alerts: cached?.alerts || [] }
    writeCache(VULN_CACHE_FILE, { lastCheck: Date.now(), ...fallback })
    return fallback
  }
}

/**
 * Compare semver-like version strings. Positive if a > b, negative if a < b, 0 if equal.
 */
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number)
  const pb = b.split('.').map(Number)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0)
    if (diff !== 0) return diff
  }
  return 0
}

// ===== Cache helpers =====

function readCache<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, 'utf-8')) as T
  } catch {
    return null
  }
}

function writeCache(path: string, data: unknown): void {
  try {
    mkdirSync(CACHE_DIR, { recursive: true, mode: 0o700 })
    writeFileSync(path, JSON.stringify(data), { mode: 0o600 })
  } catch { /* ignore */ }
}
