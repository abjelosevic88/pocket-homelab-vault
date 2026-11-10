// The unlocked vault for the whole app: status, unlock / lock, the decrypted
// items and folders, and the actions on them. Locks itself after the idle
// time set in Settings, and when the tab is reloaded.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api, V1 } from './api'
import { useApp } from './app-context'
import { Session, TYPE_LOGIN, type Folder, type Item, type VaultStatus } from './vault'
import type { Kdf } from './crypto'

type State = 'loading' | 'none' | 'locked' | 'unlocked'

interface VaultCtx {
  state: State
  status: VaultStatus | null
  session: Session | null
  items: Item[]
  folders: Folder[]
  syncing: boolean
  syncedAt: number
  unlock: (password: string, code?: string, remember?: boolean) => Promise<void>
  lock: () => void
  reloadStatus: () => Promise<void>
  sync: () => Promise<void>
  saveItem: (it: Item) => Promise<Item>
  deleteItem: (it: Item, forever?: boolean) => Promise<void>
  restoreItem: (it: Item) => Promise<void>
  setFavorite: (it: Item, fav: boolean) => Promise<void>
  moveItems: (ids: string[], folderId: string | null) => Promise<void>
  archiveItem: (it: Item, on: boolean) => Promise<void>
  saveFolder: (name: string, id?: string) => Promise<Folder>
  deleteFolder: (id: string) => Promise<void>
  emptyBin: () => Promise<void>
}

const Ctx = createContext<VaultCtx>(null!)
export const useVault = () => useContext(Ctx)

export function VaultProvider({ children }: { children: React.ReactNode }) {
  const { user, settings } = useApp()
  const [state, setState] = useState<State>('loading')
  const [status, setStatus] = useState<VaultStatus | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [items, setItems] = useState<Item[]>([])
  const [folders, setFolders] = useState<Folder[]>([])
  const [syncing, setSyncing] = useState(false)
  const [syncedAt, setSyncedAt] = useState(0)
  const revision = useRef<number>(0)
  const sessRef = useRef<Session | null>(null)
  sessRef.current = session

  const reloadStatus = useCallback(async () => {
    const st = await api.get<VaultStatus>(`${V1}/vault/status`)
    setStatus(st)
    setState(s => !st.has_vault ? 'none' : s === 'unlocked' ? 'unlocked' : 'locked')
  }, [])
  useEffect(() => { if (user) reloadStatus().catch(() => setState('locked')) }, [user, reloadStatus])

  const lock = useCallback(() => {
    setSession(null); setItems([]); setFolders([]); revision.current = 0
    setState(s => (s === 'unlocked' ? 'locked' : s))
  }, [])

  const syncWith = useCallback(async (s: Session) => {
    setSyncing(true)
    try {
      const data = await s.call<{ ciphers: Record<string, any>[]; folders: { id: string; name: string }[] }>('GET', '/sync?excludeDomains=true')
      const fs: Folder[] = []
      for (const f of data.folders) { try { fs.push({ id: f.id, name: await s.folderName(f) }) } catch { fs.push({ id: f.id, name: 'Folder' }) } }
      fs.sort((a, b) => a.name.localeCompare(b.name))
      const its = await Promise.all(data.ciphers.map(c => s.decryptItem(c)))
      its.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }))
      setFolders(fs)
      setItems(its)
      setSyncedAt(Date.now())
      revision.current = await s.call<number>('GET', '/accounts/revision-date').catch(() => Date.now())
    } finally { setSyncing(false) }
  }, [])
  const sync = useCallback(async () => { if (sessRef.current) await syncWith(sessRef.current) }, [syncWith])

  const unlock = useCallback(async (password: string, code?: string, remember?: boolean) => {
    const st = status?.kdf ? status : await api.get<VaultStatus>(`${V1}/vault/status`)
    if (!st.has_vault || !st.kdf) throw new Error('There is no vault yet.')
    const s = await Session.unlock(st.email, st.kdf as Kdf, password, code, remember)
    s.onExpired = () => lock()
    await syncWith(s)
    setSession(s)
    setState('unlocked')
  }, [status, syncWith, lock])

  // lock after the idle time (0 = only when the tab closes)
  const lockMin = settings?.lock_minutes ?? 15
  useEffect(() => {
    if (state !== 'unlocked' || !lockMin) return
    let last = Date.now()
    const touch = () => { last = Date.now() }
    const evs = ['pointerdown', 'keydown', 'scroll', 'touchstart']
    evs.forEach(e => window.addEventListener(e, touch, { passive: true }))
    const t = window.setInterval(() => { if (Date.now() - last > lockMin * 60_000) lock() }, 10_000)
    return () => { evs.forEach(e => window.removeEventListener(e, touch)); clearInterval(t) }
  }, [state, lockMin, lock])

  // pick up changes made in other apps (the extension, the phone)
  useEffect(() => {
    if (state !== 'unlocked') return
    const t = window.setInterval(async () => {
      const s = sessRef.current
      if (!s || document.hidden) return
      try { const r = await s.call<number>('GET', '/accounts/revision-date'); if (r && revision.current && r !== revision.current) await syncWith(s) } catch { /* next time */ }
    }, 20_000)
    return () => clearInterval(t)
  }, [state, syncWith])

  const need = () => { const s = sessRef.current; if (!s) throw new Error('The vault is locked.'); return s }
  const after = useCallback(async () => { const s = sessRef.current; if (s) { await syncWith(s); reloadStatus().catch(() => {}) } }, [syncWith, reloadStatus])

  const saveItem = useCallback(async (it: Item) => {
    const s = need()
    // a changed password goes into the history
    const old = items.find(x => x.id === it.id)
    if (it.type === TYPE_LOGIN && it.login && old?.login && old.login.password && old.login.password !== it.login.password) {
      it = { ...it, login: { ...it.login, passwordRevisionDate: new Date().toISOString() }, history: [{ password: old.login.password, lastUsedDate: new Date().toISOString() }, ...it.history].slice(0, 5) }
    }
    const body = await s.encryptItem(it)
    const saved = it.id ? await s.call('PUT', `/ciphers/${it.id}`, body) : await s.call('POST', '/ciphers', body)
    await after()
    return s.decryptItem(saved)
  }, [items, after])

  const value = useMemo<VaultCtx>(() => ({
    state, status, session, items, folders, syncing, syncedAt, unlock, lock, reloadStatus, sync, saveItem,
    deleteItem: async (it, forever) => { const s = need(); await s.call(forever ? 'DELETE' : 'PUT', forever ? `/ciphers/${it.id}` : `/ciphers/${it.id}/delete`); await after() },
    restoreItem: async it => { const s = need(); await s.call('PUT', `/ciphers/${it.id}/restore`); await after() },
    setFavorite: async (it, fav) => { const s = need(); await s.call('PUT', `/ciphers/${it.id}/partial`, { folderId: it.folderId, favorite: fav }); await after() },
    moveItems: async (ids, folderId) => { const s = need(); await s.call('PUT', '/ciphers/move', { ids, folderId }); await after() },
    archiveItem: async (it, on) => { const s = need(); await s.call('PUT', `/ciphers/${it.id}/${on ? 'archive' : 'unarchive'}`); await after() },
    saveFolder: async (name, id) => {
      const s = need()
      const f = await s.call<{ id: string }>(id ? 'PUT' : 'POST', id ? `/folders/${id}` : '/folders', { name: await s.encryptName(name) })
      await after()
      return { id: f.id, name }
    },
    deleteFolder: async id => { const s = need(); await s.call('DELETE', `/folders/${id}`); await after() },
    emptyBin: async () => { const s = need(); const ids = items.filter(i => i.deletedDate).map(i => i.id); if (ids.length) await s.call('POST', '/ciphers/delete', { ids }); await after() },
  }), [state, status, session, items, folders, syncing, syncedAt, unlock, lock, reloadStatus, sync, saveItem, after])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}
