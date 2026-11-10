// Vault health: weak, reused, old and exposed passwords, worked out here.
// Only the counts may be shared (Settings → Connected apps); for the breach
// check only the first five characters of a SHA-1 hash leave the browser.
import { sha1Hex } from './crypto'
import { strength } from './generator'
import { TYPE_LOGIN, type Item } from './vault'

export interface Health {
  logins: Item[]
  weak: Item[]
  reused: { password: string; items: Item[] }[]
  reusedItems: Item[]
  old: Item[]
  http: Item[]
  noPassword: Item[]
  withTotp: number
  breached: Map<string, number> // item id → times seen
  checkedBreaches: boolean
  score: number // 0–100
}

const YEAR = 365 * 24 * 3600 * 1000

export function analyse(items: Item[], breached = new Map<string, number>(), checked = false): Health {
  const logins = items.filter(i => i.type === TYPE_LOGIN && !i.deletedDate && i.login)
  const withPw = logins.filter(i => i.login!.password)
  const weak = withPw.filter(i => strength(i.login!.password).score < 2)
  const by = new Map<string, Item[]>()
  for (const i of withPw) { const p = i.login!.password; by.set(p, [...(by.get(p) || []), i]) }
  const reused = [...by.entries()].filter(([, v]) => v.length > 1).map(([password, items]) => ({ password, items })).sort((a, b) => b.items.length - a.items.length)
  const reusedItems = reused.flatMap(r => r.items)
  const now = Date.now()
  const old = withPw.filter(i => now - Date.parse(i.login!.passwordRevisionDate || i.creationDate) > YEAR)
  const http = logins.filter(i => i.login!.uris.some(u => /^http:\/\//i.test(u.uri) && !/^http:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(u.uri)))
  const noPassword = logins.filter(i => !i.login!.password && !i.login!.passkeys)
  const withTotp = logins.filter(i => i.login!.totp).length
  const bad = new Set([...weak, ...reusedItems, ...logins.filter(i => breached.has(i.id))].map(i => i.id))
  const score = withPw.length ? Math.round(100 * (1 - (bad.size + old.length * 0.25) / withPw.length)) : 100
  return { logins, weak, reused, reusedItems, old, http, noPassword, withTotp, breached, checkedBreaches: checked, score: Math.max(0, Math.min(100, score)) }
}

/** The numbers another app may see. */
export function summary(h: Health) {
  return { logins: h.logins.length, weak: h.weak.length, reused: h.reusedItems.length, old: h.old.length, breached: h.breached.size, no_password: h.noPassword.length, http: h.http.length, with_totp: h.withTotp, score: h.score, checked_breaches: h.checkedBreaches }
}

/** Asks Have I Been Pwned (k-anonymity) how often each password was seen in leaks. */
export async function checkBreaches(items: Item[], onProgress?: (done: number, total: number) => void): Promise<Map<string, number>> {
  const out = new Map<string, number>()
  const withPw = items.filter(i => i.type === TYPE_LOGIN && !i.deletedDate && i.login?.password)
  const byHash = new Map<string, Item[]>()
  for (const i of withPw) { const h = await sha1Hex(i.login!.password); byHash.set(h, [...(byHash.get(h) || []), i]) }
  const prefixes = new Map<string, string[]>()
  for (const h of byHash.keys()) prefixes.set(h.slice(0, 5), [...(prefixes.get(h.slice(0, 5)) || []), h])
  let done = 0
  for (const [prefix, hashes] of prefixes) {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' }, referrerPolicy: 'no-referrer', credentials: 'omit' })
    if (!res.ok) throw new Error(`Have I Been Pwned answered ${res.status}`)
    const lines = (await res.text()).split('\n')
    for (const line of lines) {
      const [suffix, count] = line.trim().split(':')
      const full = prefix + suffix
      if (hashes.includes(full) && Number(count) > 0) for (const it of byHash.get(full) || []) out.set(it.id, Number(count))
    }
    onProgress?.(++done, prefixes.size)
  }
  return out
}
