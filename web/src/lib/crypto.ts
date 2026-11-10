// Bitwarden's client-side encryption, in the browser (Web Crypto). The
// master password never leaves this page: it becomes the master key here,
// the server only ever gets a hash of it, and every item is decrypted and
// encrypted here with the user key.

const te = new TextEncoder()
const td = new TextDecoder()

export const b64 = {
  enc(b: Uint8Array): string { let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s) },
  dec(s: string): Uint8Array { const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out },
}

export const random = (n: number) => crypto.getRandomValues(new Uint8Array(n))

export interface Kdf { type: number; iterations: number; memory?: number | null; parallelism?: number | null }

/** The master key: PBKDF2-SHA256 over the password with the email as salt, or Argon2id. */
export async function masterKey(password: string, email: string, kdf: Kdf): Promise<Uint8Array> {
  const salt = te.encode(email.trim().toLowerCase())
  if (kdf.type === 1) {
    const { argon2id } = await import('hash-wasm')
    const s = new Uint8Array(await crypto.subtle.digest('SHA-256', salt))
    return await argon2id({ password, salt: s, iterations: kdf.iterations, parallelism: kdf.parallelism || 4, memorySize: (kdf.memory || 64) * 1024, hashLength: 32, outputType: 'binary' })
  }
  return pbkdf2(te.encode(password), salt, kdf.iterations)
}

async function pbkdf2(secret: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', secret as BufferSource, 'PBKDF2', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' }, k, 256))
}

/** What the server checks: PBKDF2(masterKey, password, 1). */
export async function masterPasswordHash(mk: Uint8Array, password: string): Promise<string> {
  return b64.enc(await pbkdf2(mk, te.encode(password), 1))
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data as BufferSource))
}

/** A 64-byte key: AES-256-CBC for the data, HMAC-SHA256 for the check. */
export class SymKey {
  constructor(readonly raw: Uint8Array) { if (raw.length !== 64) throw new Error('A vault key is 64 bytes.') }
  get enc() { return this.raw.slice(0, 32) }
  get mac() { return this.raw.slice(32) }
  static random() { return new SymKey(random(64)) }
}

/** The master key, stretched (HKDF-Expand "enc" / "mac"), unlocks the user key. */
export async function stretch(mk: Uint8Array): Promise<SymKey> {
  const one = new Uint8Array([1])
  const enc = await hmac(mk, concat(te.encode('enc'), one))
  const mac = await hmac(mk, concat(te.encode('mac'), one))
  return new SymKey(concat(enc, mac))
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let i = 0
  for (const p of parts) { out.set(p, i); i += p.length }
  return out
}

function eq(a: Uint8Array, b: Uint8Array) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0 }

export class WrongKey extends Error { constructor() { super('This could not be decrypted with your key.') } }

/** Decrypts an EncString ("2.iv|data|mac"; also the old "0." without a check). */
export async function decryptBytes(enc: string, key: SymKey): Promise<Uint8Array> {
  const dot = enc.indexOf('.')
  const type = dot > 0 ? Number(enc.slice(0, dot)) : 0
  const parts = (dot > 0 ? enc.slice(dot + 1) : enc).split('|')
  if (type !== 2 && type !== 0) throw new Error(`Encryption type ${type} isn't supported here yet.`)
  const iv = b64.dec(parts[0]), data = b64.dec(parts[1])
  if (type === 2) {
    const mac = b64.dec(parts[2] || '')
    if (!eq(await hmac(key.mac, concat(iv, data)), mac)) throw new WrongKey()
  }
  const k = await crypto.subtle.importKey('raw', key.enc as BufferSource, 'AES-CBC', false, ['decrypt'])
  try { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv as BufferSource }, k, data as BufferSource)) } catch { throw new WrongKey() }
}

export async function decrypt(enc: string | null | undefined, key: SymKey): Promise<string> {
  if (!enc) return ''
  return td.decode(await decryptBytes(enc, key))
}

export async function encryptBytes(plain: Uint8Array, key: SymKey): Promise<string> {
  const iv = random(16)
  const k = await crypto.subtle.importKey('raw', key.enc as BufferSource, 'AES-CBC', false, ['encrypt'])
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv as BufferSource }, k, plain as BufferSource))
  const mac = await hmac(key.mac, concat(iv, data))
  return `2.${b64.enc(iv)}|${b64.enc(data)}|${b64.enc(mac)}`
}

/** Encrypts text ("" and null stay null, as the apps send them). */
export async function encrypt(plain: string | null | undefined, key: SymKey): Promise<string | null> {
  if (plain == null || plain === '') return null
  return encryptBytes(te.encode(plain), key)
}

/** A new vault: the user key, wrapped with the master key, and an RSA key pair. */
export async function newVaultKeys(password: string, email: string, kdf: Kdf) {
  const mk = await masterKey(password, email, kdf)
  const hash = await masterPasswordHash(mk, password)
  const user = SymKey.random()
  const protectedKey = await encryptBytes(user.raw, await stretch(mk))
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt'])
  const pub = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))
  const priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  return { hash, user, key: protectedKey, publicKey: b64.enc(pub), privateKey: await encryptBytes(priv, user) }
}

/** SHA-1 in hex, upper case (Have I Been Pwned's range lookups). */
export async function sha1Hex(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-1', te.encode(s)))
  return Array.from(d, b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
}

// ---- authenticator codes (TOTP) ----

function base32(s: string): Uint8Array {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const clean = s.toUpperCase().replace(/[\s=-]/g, '')
  let bits = 0, val = 0
  const out: number[] = []
  for (const c of clean) {
    const i = alpha.indexOf(c)
    if (i < 0) throw new Error('not base32')
    val = (val << 5) | i; bits += 5
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8 }
  }
  return new Uint8Array(out)
}

export interface TotpSpec { secret: string; period: number; digits: number; algo: 'SHA-1' | 'SHA-256' | 'SHA-512'; steam: boolean }

/** Reads what a login keeps as its authenticator key: a bare secret, otpauth:// or steam://. */
export function parseTotp(v: string): TotpSpec | null {
  const s = v.trim()
  if (!s) return null
  if (s.toLowerCase().startsWith('steam://')) return { secret: s.slice(8), period: 30, digits: 5, algo: 'SHA-1', steam: true }
  if (s.toLowerCase().startsWith('otpauth://')) {
    try {
      const u = new URL(s)
      const q = u.searchParams
      const algo = (q.get('algorithm') || 'SHA1').toUpperCase().replace('SHA', 'SHA-') as TotpSpec['algo']
      return { secret: q.get('secret') || '', period: Number(q.get('period')) || 30, digits: Number(q.get('digits')) || 6, algo: ['SHA-1', 'SHA-256', 'SHA-512'].includes(algo) ? algo : 'SHA-1', steam: false }
    } catch { return null }
  }
  return { secret: s, period: 30, digits: 6, algo: 'SHA-1', steam: false }
}

export async function totp(spec: TotpSpec, now = Date.now()): Promise<string> {
  const key = base32(spec.secret)
  const counter = Math.floor(now / 1000 / spec.period)
  const msg = new Uint8Array(8)
  new DataView(msg.buffer).setUint32(4, counter >>> 0)
  new DataView(msg.buffer).setUint32(0, Math.floor(counter / 2 ** 32))
  const k = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: spec.algo }, false, ['sign'])
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', k, msg as BufferSource))
  const off = h[h.length - 1] & 0xf
  let code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]
  if (spec.steam) {
    const chars = '23456789BCDFGHJKMNPQRTVWXY'
    let out = ''
    for (let i = 0; i < 5; i++) { out += chars[code % chars.length]; code = Math.floor(code / chars.length) }
    return out
  }
  return String(code % 10 ** spec.digits).padStart(spec.digits, '0')
}
