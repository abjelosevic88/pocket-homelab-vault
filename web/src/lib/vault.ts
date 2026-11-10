// The web vault is a Bitwarden client like the browser extension: it signs
// in to /identity with a hash of the master password, reads /api/sync and
// decrypts here. The keys live in this tab's memory only; a reload locks.
import { b64, decrypt, decryptBytes, encrypt, masterKey, masterPasswordHash, stretch, SymKey, type Kdf } from './crypto'

export const TYPE_LOGIN = 1, TYPE_NOTE = 2, TYPE_CARD = 3, TYPE_IDENTITY = 4, TYPE_SSH = 5
export const TYPE_KEY: Record<number, string> = { 1: 'login', 2: 'secureNote', 3: 'card', 4: 'identity', 5: 'sshKey', 6: 'bankAccount', 7: 'driversLicense', 8: 'passport' }
export const TYPE_NAME: Record<number, string> = { 1: 'Login', 2: 'Note', 3: 'Card', 4: 'Identity', 5: 'SSH key', 6: 'Bank account', 7: 'Driving licence', 8: 'Passport' }
export const TYPE_ICON: Record<number, string> = { 1: 'globe', 2: 'note', 3: 'card', 4: 'id', 5: 'terminal', 6: 'wallet', 7: 'id', 8: 'id' }

export interface Uri { uri: string; match: number | null }
export interface CustomField { name: string; value: string; type: number; linkedId: number | null }
export interface Hist { password: string; lastUsedDate: string }
export interface Login { username: string; password: string; totp: string; uris: Uri[]; passwordRevisionDate: string | null; passkeys: number }
export interface Card { cardholderName: string; brand: string; number: string; expMonth: string; expYear: string; code: string }
export const IDENTITY_FIELDS = ['title', 'firstName', 'middleName', 'lastName', 'company', 'email', 'phone', 'username', 'address1', 'address2', 'address3', 'city', 'state', 'postalCode', 'country', 'ssn', 'passportNumber', 'licenseNumber'] as const
export type Identity = Record<(typeof IDENTITY_FIELDS)[number], string>
export interface SshKey { privateKey: string; publicKey: string; keyFingerprint: string }

export interface Item {
  id: string
  type: number
  name: string
  notes: string
  folderId: string | null
  favorite: boolean
  reprompt: number
  creationDate: string
  revisionDate: string
  deletedDate: string | null
  archivedDate: string | null
  login?: Login
  card?: Card
  identity?: Identity
  sshKey?: SshKey
  fields: CustomField[]
  history: Hist[]
  /** what the server sent, so fields this app doesn't edit (passkeys…) are kept */
  raw: Record<string, any>
  /** set when this item couldn't be decrypted */
  error?: string
}

export interface Folder { id: string; name: string }

export interface VaultStatus {
  has_vault: boolean; email: string; name?: string; server_url: string; kdf?: Kdf & { type: number }; hint?: string
  counts?: Record<string, number>; devices?: number; last_used?: string; two_factor?: boolean; created_at?: string; revision_date?: string; live_apps: number
}

export class TwoFactorNeeded extends Error { constructor(readonly providers: string[]) { super('Enter the code from your authenticator app.') } }
export class BWError extends Error { constructor(readonly status: number, msg: string) { super(msg) } }

const DEVICE_KEY = 'pvt-device'
function deviceId(): string {
  let id = localStorage.getItem(DEVICE_KEY)
  if (!id) { id = crypto.randomUUID(); localStorage.setItem(DEVICE_KEY, id) }
  return id
}
function deviceType(): number {
  const ua = navigator.userAgent
  if (/Edg\//.test(ua)) return 12
  if (/OPR\//.test(ua)) return 11
  if (/Firefox\//.test(ua)) return 10
  if (/Safari\//.test(ua) && !/Chrome\//.test(ua)) return 17
  return 9
}

async function bwErrorOf(res: Response): Promise<BWError> {
  let msg = res.statusText
  try {
    const j = await res.json()
    msg = j.message || j.errorModel?.message || j.error_description || j.error || msg
    if (j.TwoFactorProviders) throw new TwoFactorNeeded(j.TwoFactorProviders)
  } catch (e) { if (e instanceof TwoFactorNeeded) throw e }
  return new BWError(res.status, msg)
}

/** One unlocked vault: tokens and the user key, in memory. */
export class Session {
  access = ''
  refresh = ''
  constructor(readonly email: string, readonly key: SymKey) {}

  static async unlock(email: string, kdf: Kdf, password: string, code?: string, remember?: boolean): Promise<Session> {
    const mk = await masterKey(password, email, kdf)
    const hash = await masterPasswordHash(mk, password)
    const form = new URLSearchParams({ grant_type: 'password', username: email, password: hash, scope: 'api offline_access', client_id: 'web',
      deviceType: String(deviceType()), deviceIdentifier: deviceId(), deviceName: 'Pocket Vault web' })
    if (code) { form.set('twoFactorProvider', /^[0-9]{6}$/.test(code.replace(/\s/g, '')) ? '0' : '8'); form.set('twoFactorToken', code.replace(/\s/g, '')); form.set('twoFactorRemember', remember ? '1' : '0') }
    const remembered = localStorage.getItem('pvt-2fa:' + email)
    if (!code && remembered) { form.set('twoFactorProvider', '5'); form.set('twoFactorToken', remembered) }
    const res = await fetch('/identity/connect/token', { method: 'POST', body: form, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })
    if (!res.ok) {
      const err = await bwErrorOf(res).catch(e => e)
      if (err instanceof TwoFactorNeeded && remembered) localStorage.removeItem('pvt-2fa:' + email)
      throw err
    }
    const j = await res.json()
    if (j.TwoFactorToken) localStorage.setItem('pvt-2fa:' + email, j.TwoFactorToken)
    let user: Uint8Array
    try { user = await decryptBytes(j.Key, await stretch(mk)) } catch { throw new Error('Your vault key could not be opened with this password.') }
    const s = new Session(email, new SymKey(user))
    s.access = j.access_token
    s.refresh = j.refresh_token
    return s
  }

  private async renew(): Promise<boolean> {
    const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: this.refresh, client_id: 'web' })
    const res = await fetch('/identity/connect/token', { method: 'POST', body: form, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })
    if (!res.ok) return false
    const j = await res.json()
    this.access = j.access_token
    if (j.refresh_token) this.refresh = j.refresh_token
    return true
  }

  onExpired: () => void = () => {}

  async call<T = any>(method: string, path: string, body?: unknown, retry = true): Promise<T> {
    const res = await fetch('/api' + path, { method, headers: { Authorization: 'Bearer ' + this.access, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) })
    if (res.status === 401 && retry) {
      if (await this.renew()) return this.call<T>(method, path, body, false)
      this.onExpired()
      throw new BWError(401, 'Your session ended. Unlock again.')
    }
    if (!res.ok) throw await bwErrorOf(res)
    const text = await res.text()
    return (text ? JSON.parse(text) : undefined) as T
  }

  // ---- items ----

  private async itemKey(raw: Record<string, any>): Promise<SymKey> {
    return raw.key ? new SymKey(await decryptBytes(raw.key, this.key)) : this.key
  }

  async decryptItem(raw: Record<string, any>): Promise<Item> {
    const it: Item = { id: raw.id, type: raw.type, name: '', notes: '', folderId: raw.folderId || null, favorite: !!raw.favorite, reprompt: raw.reprompt || 0,
      creationDate: raw.creationDate, revisionDate: raw.revisionDate, deletedDate: raw.deletedDate || null, archivedDate: raw.archivedDate || null, fields: [], history: [], raw }
    try {
      const k = await this.itemKey(raw)
      const d = (v: string | null | undefined) => decrypt(v, k)
      it.name = await d(raw.name)
      it.notes = await d(raw.notes)
      for (const f of raw.fields || []) it.fields.push({ name: await d(f.name), value: await d(f.value), type: f.type ?? 0, linkedId: f.linkedId ?? null })
      for (const h of raw.passwordHistory || []) it.history.push({ password: await d(h.password), lastUsedDate: h.lastUsedDate })
      if (raw.type === TYPE_LOGIN && raw.login) {
        const l = raw.login
        const uris: Uri[] = []
        for (const u of l.uris || []) uris.push({ uri: await d(u.uri), match: u.match ?? null })
        it.login = { username: await d(l.username), password: await d(l.password), totp: await d(l.totp), uris, passwordRevisionDate: l.passwordRevisionDate || null, passkeys: (l.fido2Credentials || []).length }
      } else if (raw.type === TYPE_CARD && raw.card) {
        const c = raw.card
        it.card = { cardholderName: await d(c.cardholderName), brand: await d(c.brand), number: await d(c.number), expMonth: await d(c.expMonth), expYear: await d(c.expYear), code: await d(c.code) }
      } else if (raw.type === TYPE_IDENTITY && raw.identity) {
        const id = {} as Identity
        for (const f of IDENTITY_FIELDS) id[f] = await d(raw.identity[f])
        it.identity = id
      } else if (raw.type === TYPE_SSH && raw.sshKey) {
        it.sshKey = { privateKey: await d(raw.sshKey.privateKey), publicKey: await d(raw.sshKey.publicKey), keyFingerprint: await d(raw.sshKey.keyFingerprint) }
      }
    } catch (e) {
      it.error = (e as Error).message
      if (!it.name) it.name = 'An item this page can’t open'
    }
    return it
  }

  /** The request body for an item, encrypted with its own key (or the user key). */
  async encryptItem(it: Item): Promise<Record<string, any>> {
    const raw = it.raw || {}
    const k = await this.itemKey(raw)
    const e = (v: string | null | undefined) => encrypt(v, k)
    const body: Record<string, any> = {
      type: it.type, name: await e(it.name || 'Untitled'), notes: await e(it.notes), folderId: it.folderId, favorite: it.favorite, reprompt: it.reprompt,
      key: raw.key ?? null, organizationId: null, archivedDate: it.archivedDate, lastKnownRevisionDate: raw.revisionDate,
    }
    body.fields = it.fields.length ? await Promise.all(it.fields.map(async f => ({ name: await e(f.name), value: await e(f.value), type: f.type, linkedId: f.linkedId }))) : null
    body.passwordHistory = it.history.length ? await Promise.all(it.history.slice(0, 5).map(async h => ({ password: await e(h.password), lastUsedDate: h.lastUsedDate }))) : null
    const typed: Record<string, any> = { ...(raw[TYPE_KEY[it.type]] || {}) }
    if (it.type === TYPE_LOGIN && it.login) {
      const l = it.login
      typed.username = await e(l.username)
      typed.password = await e(l.password)
      typed.totp = await e(l.totp)
      typed.passwordRevisionDate = l.passwordRevisionDate
      typed.uris = await Promise.all(l.uris.filter(u => u.uri.trim()).map(async u => ({ uri: await e(u.uri.trim()), match: u.match, uriChecksum: await e(b64.enc(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(u.uri.trim()))))) })))
      delete typed.uri
      if (!typed.fido2Credentials) typed.fido2Credentials = []
    } else if (it.type === TYPE_CARD && it.card) {
      for (const [f, v] of Object.entries(it.card)) typed[f] = await e(v)
    } else if (it.type === TYPE_IDENTITY && it.identity) {
      for (const f of IDENTITY_FIELDS) typed[f] = await e(it.identity[f])
    } else if (it.type === TYPE_NOTE) {
      typed.type = 0
    } else if (it.type === TYPE_SSH && it.sshKey) {
      for (const [f, v] of Object.entries(it.sshKey)) typed[f] = await e(v)
    }
    body[TYPE_KEY[it.type]] = typed
    return body
  }

  async folderName(raw: { name: string }): Promise<string> { return decrypt(raw.name, this.key) }
  async encryptName(name: string): Promise<string> { return (await encrypt(name, this.key)) || '' }
}

/** A blank item of a type, for the "new item" form. */
export function blankItem(type: number, folderId: string | null = null): Item {
  const it: Item = { id: '', type, name: '', notes: '', folderId, favorite: false, reprompt: 0, creationDate: '', revisionDate: '', deletedDate: null, archivedDate: null, fields: [], history: [], raw: {} }
  if (type === TYPE_LOGIN) it.login = { username: '', password: '', totp: '', uris: [{ uri: '', match: null }], passwordRevisionDate: null, passkeys: 0 }
  if (type === TYPE_CARD) it.card = { cardholderName: '', brand: '', number: '', expMonth: '', expYear: '', code: '' }
  if (type === TYPE_IDENTITY) it.identity = Object.fromEntries(IDENTITY_FIELDS.map(f => [f, ''])) as Identity
  if (type === TYPE_SSH) it.sshKey = { privateKey: '', publicKey: '', keyFingerprint: '' }
  return it
}

/** The host of a login's first web address, for its icon ("" when there's none). */
export function hostOf(it: Item): string {
  const u = it.login?.uris.find(x => /^https?:\/\//i.test(x.uri) || /^[\w-]+(\.[\w-]+)+/.test(x.uri))?.uri
  if (!u) return ''
  try { return new URL(/^https?:\/\//i.test(u) ? u : 'https://' + u).hostname } catch { return '' }
}

/** One line under an item's name in the list. */
export function subtitle(it: Item): string {
  if (it.error) return it.error
  if (it.login) return it.login.username || hostOf(it)
  if (it.card) return [it.card.brand, it.card.number ? '•••• ' + it.card.number.slice(-4) : ''].filter(Boolean).join(' ')
  if (it.identity) return [it.identity.firstName, it.identity.lastName].filter(Boolean).join(' ') || it.identity.email
  if (it.sshKey) return it.sshKey.keyFingerprint
  return it.notes.split('\n')[0].slice(0, 80)
}

export function cardBrand(n: string): string {
  const d = n.replace(/\D/g, '')
  if (/^4/.test(d)) return 'Visa'
  if (/^(5[1-5]|2[2-7])/.test(d)) return 'Mastercard'
  if (/^3[47]/.test(d)) return 'Amex'
  if (/^6(011|5)/.test(d)) return 'Discover'
  if (/^35/.test(d)) return 'JCB'
  if (/^3(0[0-5]|[68])/.test(d)) return 'Diners Club'
  if (/^(62|81)/.test(d)) return 'UnionPay'
  if (/^(50|5[6-9]|6)/.test(d)) return 'Maestro'
  return ''
}

/** The last day a card works (YYYY-MM-DD) or "". */
export function cardExpiry(c: Card): string {
  const m = Number(c.expMonth), y0 = Number(c.expYear)
  if (!m || m < 1 || m > 12 || !y0) return ''
  const y = y0 < 100 ? 2000 + y0 : y0
  const last = new Date(Date.UTC(y, m, 0)).getUTCDate()
  return `${y}-${String(m).padStart(2, '0')}-${String(last).padStart(2, '0')}`
}
