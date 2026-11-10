// The app shell: sidebar, top bar, search palette, shortcuts — the Pocket Calendar layout.
import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, V1 } from '../lib/api'
import { useApp } from '../lib/app-context'
import { useVault } from '../lib/vault-context'
import { blankItem, TYPE_CARD, TYPE_IDENTITY, TYPE_LOGIN, TYPE_NOTE, type Item } from '../lib/vault'
import { Icon } from './icons'
import { Sidebar } from './Sidebar'
import { CommandPalette, type PaletteCommand } from './CommandPalette'
import { ShortcutsSheet } from './ShortcutsSheet'
import { ItemForm } from './ItemForm'
import { FolderModal } from './FolderModal'
import { LockScreen } from './LockScreen'
import { Avatar, type Anchor, type MenuItem, Menu, MenuButton, modalOpen, rectOf, useIsMobile, useMediaQuery } from './ui'

const SIDEBAR_KEY = 'pvt-sidebar'

/** The page's own name for the top bar breadcrumb. */
const CrumbCtx = createContext<(t: string) => void>(() => {})
export function useCrumb(title: string | undefined) {
  const set = useContext(CrumbCtx)
  useEffect(() => { set(title || ''); return () => set('') }, [title, set])
}

export type CreateKind = 'login' | 'card' | 'identity' | 'note' | 'folder'

/** Open a create action from anywhere (a page's button). */
export const openCreate = (k: CreateKind) => window.dispatchEvent(new CustomEvent('pvt:create', { detail: { kind: k } }))
/** Open the edit form for an item. */
export const openEdit = (it: Item) => window.dispatchEvent(new CustomEvent('pvt:edit', { detail: { item: it } }))

/** The "New" menu: the sidebar's button and the phone's + button. */
export function createItems(onCreate: (k: CreateKind) => void): MenuItem[] {
  return [
    { label: 'Login', icon: 'globe', hint: 'N', onSelect: () => onCreate('login') },
    { label: 'Card', icon: 'card', onSelect: () => onCreate('card') },
    { label: 'Identity', icon: 'id', onSelect: () => onCreate('identity') },
    { label: 'Note', icon: 'note', onSelect: () => onCreate('note') },
    'sep',
    { label: 'Folder', icon: 'folder-plus', onSelect: () => onCreate('folder') },
  ]
}

const TYPE_OF: Record<Exclude<CreateKind, 'folder'>, number> = { login: TYPE_LOGIN, card: TYPE_CARD, identity: TYPE_IDENTITY, note: TYPE_NOTE }

export default function Layout() {
  const navigate = useNavigate()
  const loc = useLocation()
  const mobile = useIsMobile()
  const narrow = useMediaQuery('(max-width: 1099px)')
  const drawer = mobile || narrow
  const vault = useVault()
  const [sidebarOpen, setSidebarOpen] = useState(() => !drawer && localStorage.getItem(SIDEBAR_KEY) !== '0')
  useEffect(() => { setSidebarOpen(!drawer && localStorage.getItem(SIDEBAR_KEY) !== '0') }, [drawer])
  const drawerOpenedAt = useRef(0)
  const toggleSidebar = () => setSidebarOpen(o => { drawerOpenedAt.current = performance.now(); const n = !o; if (!drawer) localStorage.setItem(SIDEBAR_KEY, n ? '1' : '0'); return n })
  const closeDrawer = () => { if (drawer) setSidebarOpen(false) }
  useEffect(() => { document.querySelector('.content')?.scrollTo({ top: 0 }) }, [loc.pathname])

  const [crumb, setCrumbRaw] = useState('')
  const setCrumb = useCallback((t: string) => setCrumbRaw(t), [])

  const [palette, setPalette] = useState(false)
  const [shortcuts, setShortcuts] = useState(false)
  const [editing, setEditing] = useState<Item | null>(null)
  const [folderModal, setFolderModal] = useState(false)
  const [fabMenu, setFabMenu] = useState<Anchor | null>(null)
  const unlocked = vault.state === 'unlocked'

  const create = (k: CreateKind) => {
    closeDrawer()
    if (!unlocked) return
    if (k === 'folder') { setFolderModal(true); return }
    const f = new URLSearchParams(loc.search).get('f') || ''
    setEditing(blankItem(TYPE_OF[k], f.startsWith('folder:') ? f.slice(7) : null))
  }
  const createRef = useRef(create)
  createRef.current = create

  useEffect(() => {
    const open = () => setShortcuts(true)
    const make = (e: Event) => { const d = (e as CustomEvent<{ kind: CreateKind }>).detail; createRef.current(d.kind) }
    const edit = (e: Event) => setEditing((e as CustomEvent<{ item: Item }>).detail.item)
    window.addEventListener('pvt:shortcuts', open)
    window.addEventListener('pvt:create', make)
    window.addEventListener('pvt:edit', edit)
    return () => { window.removeEventListener('pvt:shortcuts', open); window.removeEventListener('pvt:create', make); window.removeEventListener('pvt:edit', edit) }
  }, [])
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (unlocked) setPalette(p => !p); return }
      if (e.metaKey || e.ctrlKey || e.altKey) return
      if (t.closest('input, textarea, select, [contenteditable="true"]') || modalOpen() || document.querySelector('.menu, .popover, .sel-pop')) return
      if (!unlocked && e.key !== '?') return
      const go = (to: string) => { e.preventDefault(); navigate(to) }
      switch (e.key) {
        case '/': e.preventDefault(); setPalette(true); break
        case '?': e.preventDefault(); setShortcuts(true); break
        case 'n': e.preventDefault(); createRef.current('login'); break
        case 'l': e.preventDefault(); vault.lock(); break
        case 'v': go('/'); break
        case 'f': go('/?f=favorites'); break
        case 'g': go('/generator'); break
        case 'h': go('/health'); break
        case 'a': go('/activity'); break
        case ',': go('/settings'); break
        case '[': e.preventDefault(); toggleSidebar(); break
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }) // eslint-disable-line react-hooks/exhaustive-deps

  const commands: PaletteCommand[] = [
    { id: 'new', label: 'New login', icon: 'plus', hint: 'N', keywords: 'add password site', run: () => create('login') },
    { id: 'card', label: 'New card', icon: 'card', keywords: 'add credit debit', run: () => create('card') },
    { id: 'note', label: 'New note', icon: 'note', keywords: 'add secure text', run: () => create('note') },
    { id: 'vault', label: 'All items', icon: 'lock', hint: 'V', run: () => navigate('/') },
    { id: 'fav', label: 'Favourites', icon: 'star', hint: 'F', run: () => navigate('/?f=favorites') },
    { id: 'gen', label: 'Password generator', icon: 'dice', hint: 'G', keywords: 'random passphrase create strong', run: () => navigate('/generator') },
    { id: 'health', label: 'Health: weak and reused passwords', icon: 'shield-check', hint: 'H', keywords: 'security report breach pwned', run: () => navigate('/health') },
    { id: 'activity', label: 'Signed-in apps and activity', icon: 'smartphone', hint: 'A', keywords: 'devices sessions sign out', run: () => navigate('/activity') },
    { id: 'apps', label: 'Use with the Bitwarden apps', icon: 'puzzle', keywords: 'extension iphone android desktop cli server url', run: () => navigate('/apps') },
    { id: 'bin', label: 'Bin', icon: 'trash', keywords: 'deleted trash restore', run: () => navigate('/?f=bin') },
    { id: 'lock', label: 'Lock the vault', icon: 'lock', hint: 'L', run: () => vault.lock() },
    { id: 'security', label: 'Settings: security', icon: 'shield', keywords: 'master password two-step 2fa authenticator kdf', run: () => navigate('/settings/security') },
    { id: 'settings', label: 'Settings', icon: 'settings', hint: ',', run: () => navigate('/settings') },
    { id: 'shortcuts', label: 'Keyboard shortcuts', icon: 'keyboard', hint: '?', run: () => setShortcuts(true) },
  ]

  return (
    <CrumbCtx.Provider value={setCrumb}>
      <div className={`app ${sidebarOpen ? 'with-sidebar' : 'no-sidebar'} ${mobile ? 'is-mobile' : ''} ${drawer ? 'drawer-mode' : ''}`}>
        {drawer && sidebarOpen && <div className="drawer-backdrop" onClick={e => { if (e.timeStamp - drawerOpenedAt.current > 400) setSidebarOpen(false) }} />}
        <div className={`sidebar-wrap ${sidebarOpen ? 'open' : ''}`}>
          <Sidebar onCreate={create} onNavigate={closeDrawer} />
        </div>
        <div className="main">
          <TopBar onMenu={toggleSidebar} onPalette={() => setPalette(true)} mobile={mobile} compact={narrow} sidebarOpen={sidebarOpen} crumb={crumb} />
          <main className="content"><div className="content-inner">{unlocked ? <Outlet /> : <LockScreen />}</div></main>
        </div>
        {mobile && unlocked && <button type="button" className="fab" aria-label="New item" title="New item" aria-haspopup="menu" aria-expanded={!!fabMenu} onClick={e => setFabMenu(fabMenu ? null : rectOf(e.currentTarget))}><Icon name="plus" size={24} strokeWidth={2.2} /></button>}
        {fabMenu && <Menu anchor={fabMenu} align="right" items={createItems(create)} onClose={() => setFabMenu(null)} width={220} />}
        {palette && unlocked && <CommandPalette onClose={() => setPalette(false)} commands={commands} />}
        {shortcuts && <ShortcutsSheet onClose={() => setShortcuts(false)} />}
        {editing && unlocked && <ItemForm item={editing} onClose={() => setEditing(null)} onSaved={it => { setEditing(null); navigate(`/item/${it.id}${loc.search}`) }} />}
        {folderModal && unlocked && <FolderModal onClose={() => setFolderModal(false)} onSaved={f => { setFolderModal(false); navigate(`/?f=folder:${f.id}`) }} />}
      </div>
    </CrumbCtx.Provider>
  )
}

const SECTION: Record<string, [string, string]> = { '': ['Vault', '/'], item: ['Vault', '/'], generator: ['Generator', '/generator'], health: ['Health', '/health'], activity: ['Apps & activity', '/activity'], apps: ['Bitwarden apps', '/apps'] }

function TopBar({ onMenu, onPalette, mobile, compact, sidebarOpen, crumb }: { onMenu: () => void; onPalette: () => void; mobile: boolean; compact: boolean; sidebarOpen: boolean; crumb: string }) {
  const { user, themeMode, setThemeMode, status, setUser } = useApp()
  const vault = useVault()
  const navigate = useNavigate()
  const loc = useLocation()
  const [section, sectionTo] = SECTION[loc.pathname.split('/')[1] || ''] || ['', '/']
  const unlocked = vault.state === 'unlocked'
  const signOut = async () => { vault.lock(); await api.post(`${V1}/auth/logout`).catch(() => {}); setUser(null); navigate('/login') }
  const avatarMenu = (): MenuItem[] => [
    { heading: user?.name || user?.email || '' },
    { label: 'Profile', icon: 'user', onSelect: () => navigate('/settings/profile') },
    { label: 'Security', icon: 'shield', onSelect: () => navigate('/settings/security') },
    { label: 'Settings', icon: 'settings', onSelect: () => navigate('/settings'), hint: ',' },
    { label: 'Keyboard shortcuts', icon: 'keyboard', onSelect: () => window.dispatchEvent(new CustomEvent('pvt:shortcuts')), hint: '?' },
    'sep',
    { heading: 'Appearance' },
    { label: 'System', checked: themeMode === 'system', onSelect: () => setThemeMode('system') },
    { label: 'Light', checked: themeMode === 'light', onSelect: () => setThemeMode('light') },
    { label: 'Dark', checked: themeMode === 'dark', onSelect: () => setThemeMode('dark') },
    ...(unlocked ? ['sep' as const, { label: 'Lock the vault', icon: 'lock', hint: 'L', onSelect: () => vault.lock() }] : []),
    ...(status?.auth_mode === 'local' ? [...(unlocked ? [] : ['sep' as const]), { label: 'Sign out', icon: 'log-out', onSelect: signOut }] : []),
  ]
  return (
    <header className="topbar">
      <button type="button" className="btn ghost icon-only" onClick={onMenu} aria-label={sidebarOpen ? 'Hide the sidebar' : 'Show the sidebar'} title="Menu ([)"><Icon name={mobile || compact ? 'menu' : 'sidebar'} size={18} /></button>
      <h1 className="range-title">
        {crumb ? <><button type="button" className="crumb" onClick={() => navigate(sectionTo)}>{section}</button><Icon name="chevron-right" size={16} className="crumb-sep" /><span className="ellipsis">{crumb}</span></> : section}
      </h1>
      <span className="spacer" />
      <button type="button" className="btn ghost icon-only" onClick={onPalette} aria-label="Search" title="Search (⌘K or /)" disabled={!unlocked}><Icon name="search" size={18} /></button>
      <button type="button" className="btn ghost icon-only" onClick={() => vault.lock()} aria-label="Lock the vault" title="Lock the vault (L)" disabled={!unlocked}><Icon name="lock" size={18} /></button>
      <MenuButton label="Account" className="avatar-btn" align="right" width={220} items={avatarMenu}>
        <Avatar name={user?.name} email={user?.email} size={30} />
      </MenuButton>
    </header>
  )
}
