// Left column: the New button, the vault's filters with counts, folders and tools — the Pocket Calendar sidebar.
import { useMemo, useState } from 'react'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { useApp } from '../lib/app-context'
import { useVault } from '../lib/vault-context'
import { TYPE_CARD, TYPE_IDENTITY, TYPE_LOGIN, TYPE_NOTE, TYPE_SSH } from '../lib/vault'
import { Icon } from './icons'
import { createItems, type CreateKind } from './Layout'
import { type Anchor, Menu, rectOf } from './ui'

export function Sidebar({ onCreate, onNavigate }: { onCreate: (k: CreateKind) => void; onNavigate: () => void }) {
  const { status, settings } = useApp()
  const { state, items, folders } = useVault()
  const navigate = useNavigate()
  const loc = useLocation()
  const [menu, setMenu] = useState<Anchor | null>(null)
  const title = settings?.title || status?.title || 'Pocket Vault'
  const unlocked = state === 'unlocked'
  const f = loc.pathname === '/' || loc.pathname.startsWith('/item/') ? new URLSearchParams(loc.search).get('f') || 'all' : ''

  const counts = useMemo(() => {
    const live = items.filter(i => !i.deletedDate && !i.archivedDate)
    const by = (t: number) => live.filter(i => i.type === t).length
    const folder: Record<string, number> = {}
    for (const i of live) if (i.folderId) folder[i.folderId] = (folder[i.folderId] || 0) + 1
    return { all: live.length, favorites: live.filter(i => i.favorite).length, login: by(TYPE_LOGIN), card: by(TYPE_CARD), identity: by(TYPE_IDENTITY), note: by(TYPE_NOTE), ssh: by(TYPE_SSH),
      none: live.filter(i => !i.folderId).length, folder, bin: items.filter(i => i.deletedDate).length, archive: items.filter(i => i.archivedDate && !i.deletedDate).length }
  }, [items])

  const filters: { f: string; label: string; icon: string; n?: number; hide?: boolean }[] = [
    { f: 'all', label: 'All items', icon: 'lock', n: counts.all },
    { f: 'favorites', label: 'Favourites', icon: 'star', n: counts.favorites },
    { f: 'type:1', label: 'Logins', icon: 'globe', n: counts.login },
    { f: 'type:3', label: 'Cards', icon: 'card', n: counts.card },
    { f: 'type:4', label: 'Identities', icon: 'id', n: counts.identity },
    { f: 'type:2', label: 'Notes', icon: 'note', n: counts.note },
    { f: 'type:5', label: 'SSH keys', icon: 'terminal', n: counts.ssh, hide: !counts.ssh },
  ]
  const tools = [
    { to: '/generator', label: 'Generator', icon: 'dice' },
    { to: '/health', label: 'Health', icon: 'shield-check' },
    { to: '/activity', label: 'Apps & activity', icon: 'smartphone' },
    { to: '/apps', label: 'Bitwarden apps', icon: 'puzzle' },
  ]
  const go = (to: string) => { onNavigate(); navigate(to) }
  return (
    <aside className="sidebar" aria-label="Vault">
      <div className="sb-brand">
        <img src="/favicon.svg" alt="" className="sb-logo" />
        <span className="sb-title">{title !== 'Pocket Vault' ? title : <>Pocket <b>Vault</b></>}</span>
        {status?.version && <span className="sb-version" title={`Version ${status.version}`}>{/^v?\d+\.\d+/.test(status.version) ? 'v' + status.version.replace(/^v/, '').replace(/[-+].*$/, '') : status.version}</span>}
      </div>
      <button type="button" className="btn primary create-btn" aria-haspopup="menu" aria-expanded={!!menu} disabled={!unlocked} onClick={e => setMenu(menu ? null : rectOf(e.currentTarget))}>
        <Icon name="plus" size={15} strokeWidth={2.2} />New<Icon name="chevron-down" size={15} className="create-caret" />
      </button>
      {menu && <Menu anchor={menu} items={createItems(onCreate)} onClose={() => setMenu(null)} width={220} />}

      {unlocked ? <>
        <nav className="sb-nav" aria-label="Vault">
          {filters.filter(x => !x.hide).map(x => (
            <button key={x.f} type="button" className={`sb-nav-item ${f === x.f ? 'active' : ''}`} onClick={() => go(x.f === 'all' ? '/' : `/?f=${x.f}`)}>
              <Icon name={x.icon} size={16} />{x.label}{!!x.n && <span className="sb-count">{x.n}</span>}
            </button>
          ))}
        </nav>
        <section className="sb-sec">
          <h4 className="sb-h"><span className="sb-h-btn">Folders</span><button type="button" className="sb-h-add" aria-label="New folder" title="New folder" onClick={() => onCreate('folder')}><Icon name="plus" size={14} /></button></h4>
          <nav className="sb-nav" aria-label="Folders">
            {folders.map(fo => (
              <button key={fo.id} type="button" className={`sb-nav-item ${f === 'folder:' + fo.id ? 'active' : ''}`} onClick={() => go(`/?f=folder:${fo.id}`)}>
                <Icon name="folder" size={16} /><span className="ellipsis">{fo.name}</span>{!!counts.folder[fo.id] && <span className="sb-count">{counts.folder[fo.id]}</span>}
              </button>
            ))}
            <button type="button" className={`sb-nav-item ${f === 'nofolder' ? 'active' : ''}`} onClick={() => go('/?f=nofolder')}>
              <Icon name="folder" size={16} className="muted" />No folder{!!counts.none && <span className="sb-count">{counts.none}</span>}
            </button>
            {counts.archive > 0 && <button type="button" className={`sb-nav-item ${f === 'archive' ? 'active' : ''}`} onClick={() => go('/?f=archive')}><Icon name="archive" size={16} />Archive<span className="sb-count">{counts.archive}</span></button>}
            <button type="button" className={`sb-nav-item ${f === 'bin' ? 'active' : ''}`} onClick={() => go('/?f=bin')}><Icon name="trash" size={16} />Bin{!!counts.bin && <span className="sb-count">{counts.bin}</span>}</button>
          </nav>
        </section>
      </> : <div className="sb-sec muted small sb-locked"><Icon name="lock" size={15} />{state === 'none' ? 'No vault yet' : 'The vault is locked'}</div>}

      <section className="sb-sec">
        <h4 className="sb-h"><span className="sb-h-btn">Tools</span></h4>
        <nav className="sb-nav" aria-label="Tools">
          {tools.map(t => (
            <NavLink key={t.to} to={t.to} onClick={onNavigate} className={({ isActive }) => `sb-nav-item ${isActive ? 'active' : ''}`}><Icon name={t.icon} size={16} />{t.label}</NavLink>
          ))}
        </nav>
      </section>

      <div className="sb-foot">
        <Link to="/settings" className="sb-foot-link" onClick={onNavigate}><Icon name="settings" size={15} />Settings</Link>
        <button type="button" className="sb-foot-link" onClick={() => { onNavigate(); window.dispatchEvent(new CustomEvent('pvt:shortcuts')) }}><Icon name="keyboard" size={15} />Shortcuts</button>
      </div>
    </aside>
  )
}
