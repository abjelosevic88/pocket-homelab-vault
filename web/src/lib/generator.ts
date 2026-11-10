// The password generator and a strength estimate, all in the browser.

export interface GenOptions { kind: 'password' | 'passphrase'; length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; avoid: boolean; words: number; separator: string; capital: boolean; number: boolean }

export const DEFAULT_GEN: GenOptions = { kind: 'password', length: 20, upper: true, lower: true, digits: true, symbols: true, avoid: false, words: 4, separator: '-', capital: true, number: true }

/** A uniform random integer in [0, n) (rejection sampling, no bias). */
export function randInt(n: number): number {
  const max = Math.floor(0xffffffff / n) * n
  const buf = new Uint32Array(1)
  for (;;) { crypto.getRandomValues(buf); if (buf[0] < max) return buf[0] % n }
}

const SETS = { upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lower: 'abcdefghijklmnopqrstuvwxyz', digits: '0123456789', symbols: '!@#$%^&*-_=+?' }
const LOOKALIKE = /[Il1O0o]/g

let words: string[] | null = null
export async function loadWords(): Promise<string[]> { if (!words) words = (await import('./words')).default; return words }

export async function generate(o: GenOptions): Promise<string> {
  if (o.kind === 'passphrase') {
    const list = await loadWords()
    const n = Math.max(3, Math.min(20, o.words))
    const ws = Array.from({ length: n }, () => list[randInt(list.length)])
    const out = ws.map(w => (o.capital ? w[0].toUpperCase() + w.slice(1) : w))
    if (o.number) { const i = randInt(out.length); out[i] += String(randInt(10)) }
    return out.join(o.separator)
  }
  const sets = (['upper', 'lower', 'digits', 'symbols'] as const).filter(k => o[k]).map(k => o.avoid ? SETS[k].replace(LOOKALIKE, '') : SETS[k])
  if (!sets.length) sets.push(SETS.lower)
  const len = Math.max(5, Math.min(128, o.length))
  const all = sets.join('')
  // one of each chosen kind, the rest from all of them, then shuffle
  const chars = sets.map(s => s[randInt(s.length)])
  while (chars.length < len) chars.push(all[randInt(all.length)])
  for (let i = chars.length - 1; i > 0; i--) { const j = randInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]] }
  return chars.join('')
}

/** Bits of entropy the generator puts in (what it would take to guess). */
export function genBits(o: GenOptions): number {
  if (o.kind === 'passphrase') return Math.round(o.words * Math.log2(7776) + (o.number ? Math.log2(10 * o.words) : 0))
  const pool = (o.upper ? 26 : 0) + (o.lower ? 26 : 0) + (o.digits ? 10 : 0) + (o.symbols ? 13 : 0) || 26
  return Math.round(o.length * Math.log2(pool))
}

// ---- strength of a password someone typed ----

const COMMON = new Set(['password', 'password1', '123456', '12345678', '123456789', '1234567890', 'qwerty', 'qwertyuiop', 'abc123', 'letmein', 'welcome', 'admin', 'iloveyou', 'monkey', 'dragon',
  'football', 'baseball', 'master', 'shadow', 'sunshine', 'princess', 'trustno1', 'passw0rd', 'login', 'starwars', 'whatever', 'hello', 'freedom', 'superman', 'batman', '111111', '000000',
  'zaq12wsx', 'asdfgh', 'asdfghjkl', 'changeme', 'secret', 'default', 'root', 'test', 'guest', 'summer', 'winter', 'spring', 'autumn', 'netflix', 'google', 'facebook', 'lozinka', 'sifra'])

export interface Strength { score: 0 | 1 | 2 | 3 | 4; label: string; bits: number }

/** A rough estimate (0 very weak … 4 strong) without any network. */
export function strength(pw: string): Strength {
  if (!pw) return { score: 0, label: 'Empty', bits: 0 }
  const lower = pw.toLowerCase()
  const base = lower.replace(/[0-9!@#$%^&*._-]+$/, '').replace(/^[0-9]+/, '')
  let pool = 0
  if (/[a-z]/.test(pw)) pool += 26
  if (/[A-Z]/.test(pw)) pool += 26
  if (/[0-9]/.test(pw)) pool += 10
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 20
  let bits = pw.length * Math.log2(pool || 1)
  // what people do: repeats, runs, years, a word with a number on the end
  const uniq = new Set(pw).size
  if (uniq <= 3) bits = Math.min(bits, 10)
  if (/(.)\1{2,}/.test(pw)) bits -= 8
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf|zxcv)/i.test(pw)) bits -= 12
  if (/(19|20)\d{2}/.test(pw)) bits -= 6
  if (COMMON.has(lower) || COMMON.has(base) || /^(summer|winter|spring|autumn|password|welcome|admin)\d*[!@#$]*$/i.test(pw)) bits = Math.min(bits, 12)
  if (/^[a-z]+\d{1,4}[!@#$]?$/i.test(pw) && pw.length < 12) bits = Math.min(bits, 28)
  bits = Math.max(0, Math.round(bits))
  const score: Strength['score'] = bits < 28 ? 0 : bits < 40 ? 1 : bits < 56 ? 2 : bits < 72 ? 3 : 4
  return { score, label: ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'][score], bits }
}
