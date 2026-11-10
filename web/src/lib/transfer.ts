// Import and export, in the browser: Bitwarden's JSON (plain, or encrypted
// with this vault's key), Bitwarden's CSV, and browsers' password CSVs.
import { decrypt, encrypt } from './crypto'
import { blankItem, IDENTITY_FIELDS, Session, TYPE_CARD, TYPE_IDENTITY, TYPE_KEY, TYPE_LOGIN, TYPE_NOTE, TYPE_SSH, type Folder, type Item } from './vault'

function save(name: string, text: string) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 2000)
}

const stamp = () => new Date().toISOString().slice(0, 19).replace(/[-:T]/g, '')

// ---- export ----

/** Bitwarden's "account restricted" export: as stored, readable only with this vault's key. */
export async function exportEncrypted(s: Session, items: Item[], folders: Folder[]) {
  const doc = {
    encrypted: true,
    encKeyValidation_DO_NOT_EDIT: await encrypt(crypto.randomUUID(), s.key),
    folders: await Promise.all(folders.map(async f => ({ id: f.id, name: await encrypt(f.name, s.key) }))),
    items: items.filter(i => !i.deletedDate && !i.error).map(i => {
      const r = i.raw
      const out: Record<string, unknown> = { id: r.id, organizationId: null, folderId: r.folderId ?? null, type: r.type, reprompt: r.reprompt || 0, name: r.name, notes: r.notes ?? null,
        favorite: !!r.favorite, fields: r.fields?.length ? r.fields : undefined, passwordHistory: r.passwordHistory?.length ? r.passwordHistory : null,
        revisionDate: r.revisionDate, creationDate: r.creationDate, deletedDate: null, archivedDate: r.archivedDate ?? null, collectionIds: null }
      if (r.key) out.key = r.key
      const k = TYPE_KEY[r.type]
      if (k && r[k]) out[k] = r[k]
      return out
    }),
  }
  save(`pocket_vault_export_encrypted_${stamp()}.json`, JSON.stringify(doc, null, 2))
}

/** Bitwarden's plain JSON export: every password in the open. */
export async function exportPlain(items: Item[], folders: Folder[]) {
  const doc = {
    encrypted: false,
    folders: folders.map(f => ({ id: f.id, name: f.name })),
    items: items.filter(i => !i.deletedDate && !i.error).map(i => {
      const out: Record<string, unknown> = { id: i.id, organizationId: null, folderId: i.folderId, type: i.type, reprompt: i.reprompt, name: i.name, notes: i.notes || null, favorite: i.favorite,
        fields: i.fields.length ? i.fields : undefined, passwordHistory: i.history.length ? i.history : null, revisionDate: i.revisionDate, creationDate: i.creationDate, deletedDate: null, collectionIds: null }
      if (i.login) out.login = { uris: i.login.uris.map(u => ({ match: u.match, uri: u.uri })), username: i.login.username || null, password: i.login.password || null, totp: i.login.totp || null, fido2Credentials: [] }
      if (i.type === TYPE_NOTE) out.secureNote = { type: 0 }
      if (i.card) out.card = i.card
      if (i.identity) out.identity = i.identity
      if (i.sshKey) out.sshKey = i.sshKey
      return out
    }),
  }
  save(`pocket_vault_export_${stamp()}.json`, JSON.stringify(doc, null, 2))
}

// ---- import ----

/** Imports a file; returns how many items and folders were added. */
export async function importFile(s: Session, file: File): Promise<{ items: number; folders: number }> {
  const text = await file.text()
  const t = text.trimStart()
  if (t.startsWith('{')) return importJSON(s, JSON.parse(text))
  return importCSV(s, text)
}

type Imported = { item: Item; folder: string | null }

async function post(s: Session, list: Imported[], rawCiphers?: Record<string, unknown>[], rawFolders?: { name: string }[]) {
  const names: string[] = []
  for (const x of list) if (x.folder && !names.includes(x.folder)) names.push(x.folder)
  const folders = rawFolders || await Promise.all(names.map(async n => ({ name: (await encrypt(n, s.key)) as string })))
  const ciphers = rawCiphers || await Promise.all(list.map(x => s.encryptItem(x.item)))
  const folderRelationships = rawCiphers ? [] : list.map((x, i) => ({ key: i, value: x.folder ? names.indexOf(x.folder) : -1 })).filter(r => r.value >= 0)
  if (!ciphers.length) throw new Error('No items found in that file.')
  for (const c of ciphers) delete (c as Record<string, unknown>).lastKnownRevisionDate
  await s.call('POST', '/ciphers/import', { folders, ciphers, folderRelationships })
  return { items: ciphers.length, folders: folders.length }
}

async function importJSON(s: Session, doc: any): Promise<{ items: number; folders: number }> {
  if (doc.passwordProtected) throw new Error('This export is protected with a separate password. Export again as “account restricted” or plain JSON.')
  const items: any[] = doc.items || []
  if (doc.encrypted) {
    // made with this vault's key? then it goes in as it is
    try { await decrypt(doc.encKeyValidation_DO_NOT_EDIT, s.key) } catch { throw new Error('This encrypted export belongs to another vault; it can only be imported where it was made.') }
    const folderIdx = new Map<string, number>((doc.folders || []).map((f: any, i: number) => [f.id, i]))
    const ciphers = items.map(it => { const c = { ...it }; delete c.id; delete c.folderId; delete c.collectionIds; delete c.organizationId; return c })
    const rel = items.map((it, i) => ({ key: i, value: it.folderId != null ? folderIdx.get(it.folderId) ?? -1 : -1 })).filter(r => r.value >= 0)
    await s.call('POST', '/ciphers/import', { folders: (doc.folders || []).map((f: any) => ({ name: f.name })), ciphers, folderRelationships: rel })
    return { items: ciphers.length, folders: (doc.folders || []).length }
  }
  const folderName = new Map<string, string>((doc.folders || []).map((f: any) => [f.id, f.name]))
  const list: Imported[] = items.map(src => {
    const type = [TYPE_LOGIN, TYPE_NOTE, TYPE_CARD, TYPE_IDENTITY, TYPE_SSH].includes(src.type) ? src.type : TYPE_NOTE
    const it = blankItem(type)
    it.name = src.name || 'Untitled'
    it.notes = src.notes || ''
    it.favorite = !!src.favorite
    it.reprompt = src.reprompt === 1 ? 1 : 0
    it.fields = (src.fields || []).map((f: any) => ({ name: f.name || '', value: f.value ?? '', type: f.type ?? 0, linkedId: f.linkedId ?? null }))
    it.history = (src.passwordHistory || []).filter((h: any) => h.password).map((h: any) => ({ password: h.password, lastUsedDate: h.lastUsedDate || new Date().toISOString() }))
    if (type === TYPE_LOGIN) {
      const l = src.login || {}
      it.login = { username: l.username || '', password: l.password || '', totp: l.totp || '', uris: (l.uris || []).map((u: any) => ({ uri: u.uri || '', match: u.match ?? null })), passwordRevisionDate: l.passwordRevisionDate || null, passkeys: 0 }
    }
    if (type === TYPE_CARD) it.card = { cardholderName: '', brand: '', number: '', expMonth: '', expYear: '', code: '', ...pickStrings(src.card) }
    if (type === TYPE_IDENTITY) it.identity = { ...it.identity!, ...pickStrings(src.identity, IDENTITY_FIELDS as unknown as string[]) }
    if (type === TYPE_SSH) it.sshKey = { privateKey: '', publicKey: '', keyFingerprint: '', ...pickStrings(src.sshKey) }
    return { item: it, folder: src.folderId ? folderName.get(src.folderId) || null : null }
  })
  return post(s, list)
}

function pickStrings(o: any, keys?: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(o || {})) if ((!keys || keys.includes(k)) && v != null) out[k] = String(v)
  return out
}

/** A small CSV reader (quotes, doubled quotes, line breaks inside quotes). */
export function parseCSV(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = [], cell = '', q = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++ } else q = false }
      else cell += c
    } else if (c === '"') q = true
    else if (c === ',') { row.push(cell); cell = '' }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = '' }
    else cell += c
  }
  if (cell || row.length) { row.push(cell); rows.push(row) }
  return rows.filter(r => r.some(x => x.trim()))
}

async function importCSV(s: Session, text: string) {
  const rows = parseCSV(text.replace(/^﻿/, ''))
  if (rows.length < 2) throw new Error('That CSV file has no rows.')
  const head = rows[0].map(h => h.trim().toLowerCase())
  const col = (...names: string[]) => names.map(n => head.indexOf(n)).find(i => i >= 0) ?? -1
  const get = (r: string[], i: number) => (i >= 0 ? (r[i] || '').trim() : '')
  const list: Imported[] = []
  if (head.includes('login_uri') || head.includes('login_username')) {
    // Bitwarden CSV
    const cFolder = col('folder'), cFav = col('favorite'), cType = col('type'), cName = col('name'), cNotes = col('notes'), cFields = col('fields'), cRe = col('reprompt')
    const cUri = col('login_uri'), cUser = col('login_username'), cPw = col('login_password'), cTotp = col('login_totp')
    for (const r of rows.slice(1)) {
      const note = get(r, cType) === 'note'
      const it = blankItem(note ? TYPE_NOTE : TYPE_LOGIN)
      it.name = get(r, cName) || 'Untitled'
      it.notes = get(r, cNotes)
      it.favorite = get(r, cFav) === '1'
      it.reprompt = get(r, cRe) === '1' ? 1 : 0
      it.fields = get(r, cFields).split('\n').filter(Boolean).map(l => { const i = l.indexOf(': '); return { name: i > 0 ? l.slice(0, i) : l, value: i > 0 ? l.slice(i + 2) : '', type: 0, linkedId: null } })
      if (!note) it.login = { username: get(r, cUser), password: get(r, cPw), totp: get(r, cTotp), uris: get(r, cUri).split(',').map(u => u.trim()).filter(Boolean).map(uri => ({ uri, match: null })), passwordRevisionDate: null, passkeys: 0 }
      list.push({ item: it, folder: get(r, cFolder) || null })
    }
  } else {
    // a browser's export: Chrome/Edge (name,url,username,password,note), Firefox (url,username,password,…), Safari (Title,URL,Username,Password,Notes,OTPAuth)
    const cName = col('name', 'title'), cUrl = col('url', 'login_uri', 'website'), cUser = col('username', 'login', 'email'), cPw = col('password'), cNote = col('note', 'notes', 'extra'), cOtp = col('otpauth', 'totp')
    if (cPw < 0) throw new Error('This CSV has no “password” column; is it a password export?')
    for (const r of rows.slice(1)) {
      const it = blankItem(TYPE_LOGIN)
      const url = get(r, cUrl)
      let host = ''
      try { host = new URL(url).hostname.replace(/^www\./, '') } catch { /* not a URL */ }
      it.name = get(r, cName) || host || url || 'Untitled'
      it.notes = get(r, cNote)
      it.login = { username: get(r, cUser), password: get(r, cPw), totp: get(r, cOtp), uris: url ? [{ uri: url, match: null }] : [], passwordRevisionDate: null, passkeys: 0 }
      list.push({ item: it, folder: null })
    }
  }
  return post(s, list)
}
