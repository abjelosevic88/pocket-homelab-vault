// The vault: the list on the left (search, filters from the sidebar), the
// open item on the right — on a phone one after the other.
import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api, V1 } from '../lib/api'
import { useApp } from '../lib/app-context'
import { useVault } from '../lib/vault-context'
import { cardExpiry, hostOf, subtitle, TYPE_CARD, TYPE_ICON, TYPE_IDENTITY, TYPE_LOGIN, TYPE_NAME, TYPE_NOTE, TYPE_SSH, type Item } from '../lib/vault'
import { masterKey, masterPasswordHash, parseTotp, totp } from '../lib/crypto'
import { strength } from '../lib/generator'
import { fmtDate, fmtDateTime } from '../lib/format'
import { useCrumb, openCreate, openEdit } from '../components/Layout'
import { useCopy } from '../components/Copy'
import { FolderModal } from '../components/FolderModal'
import { Icon } from '../components/icons'
import { Select } from '../components/Select'
import { Confirm, CoreHint, Empty, errMsg, Field, Modal, type MenuItem, MenuButton, useIsMobile, useToast } from '../components/ui'
import type { Reminder } from '../lib/types'

export function filterLabel(f: string, folders: { id: string; name: string }[]): string {
  if (f === 'favorites') return 'Favourites'
  if (f === 'bin') return 'Bin'
  if (f === 'archive') return 'Archive'
  if (f === 'nofolder') return 'No folder'
  if (f.startsWith('type:')) return ({ 1: 'Logins', 2: 'Notes', 3: 'Cards', 4: 'Identities', 5: 'SSH keys' } as Record<string, string>)[f.slice(5)] || 'Items'
  if (f.startsWith('folder:')) return folders.find(x => x.id === f.slice(7))?.name || 'Folder'
  return 'All items'
}

function matches(it: Item, f: string): boolean {
  if (f === 'bin') return !!it.deletedDate
  if (it.deletedDate) return false
  if (f === 'archive') return !!it.archivedDate
  if (it.archivedDate) return false
  if (f === 'favorites') return it.favorite
  if (f === 'nofolder') return !it.folderId
  if (f.startsWith('type:')) return it.type === Number(f.slice(5))
  if (f.startsWith('folder:')) return it.folderId === f.slice(7)
  return true
}

export default function Vault() {
  const { id } = useParams()
  const [sp] = useSearchParams()
  const navigate = useNavigate()
  const mobile = useIsMobile()
  const { items, folders, syncing, emptyBin, deleteFolder } = useVault()
  const { toast } = useToast()
  const f = sp.get('f') || 'all'
  const [q, setQ] = useState('')
  const [renaming, setRenaming] = useState(false)
  const [confirm, setConfirm] = useState<'bin' | 'folder' | null>(null)
  const search = useRef<HTMLInputElement>(null)
  const label = filterLabel(f, folders)
  const shown = useMemo(() => {
    const words = q.trim().toLowerCase().split(/\s+/).filter(Boolean)
    return items.filter(it => matches(it, f) && (!words.length || words.every(w => `${it.name} ${subtitle(it)} ${it.login?.uris.map(u => u.uri).join(' ') || ''} ${it.notes}`.toLowerCase().includes(w))))
  }, [items, f, q])
  const open = id ? items.find(i => i.id === id) : undefined
  useCrumb(open ? open.name : f !== 'all' ? label : undefined)
  const qs = f !== 'all' ? `?f=${f}` : ''

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (t.closest('input, textarea, [contenteditable="true"]') || document.querySelector('.modal-backdrop, .palette-backdrop, .menu')) return
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'j' || e.key === 'k') {
        if (!shown.length) return
        e.preventDefault()
        const i = shown.findIndex(x => x.id === id)
        const n = e.key === 'ArrowDown' || e.key === 'j' ? Math.min(shown.length - 1, i + 1) : Math.max(0, i - 1)
        navigate(`/item/${shown[n].id}${qs}`, { replace: true })
      } else if (e.key === 'Escape' && id) navigate(`/${qs}`)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [shown, id, qs, navigate])

  const folderId = f.startsWith('folder:') ? f.slice(7) : ''
  const listPane = (
    <section className="vault-list" aria-label={label}>
      <div className="vault-tools">
        <div className="search-box"><Icon name="search" size={15} /><input ref={search} value={q} onChange={e => setQ(e.target.value)} placeholder={`Search ${label.toLowerCase()}`} aria-label="Search" autoComplete="off" spellCheck={false} /></div>
        {folderId && <MenuButton label="Folder" items={[{ label: 'Rename folder', icon: 'edit', onSelect: () => setRenaming(true) }, { label: 'Delete folder', icon: 'trash', danger: true, onSelect: () => setConfirm('folder') }]}><Icon name="more" size={18} /></MenuButton>}
        {f === 'bin' && shown.length > 0 && <button type="button" className="btn sm ghost danger-text" onClick={() => setConfirm('bin')}>Empty</button>}
      </div>
      <div className="vault-count muted small">{shown.length.toLocaleString()} {shown.length === 1 ? 'item' : 'items'}{syncing ? ' · syncing' : ''}</div>
      {shown.length === 0 ? (
        <div className="vault-empty">
          {q ? <Empty title="Nothing matches" icon="search">Try another word, or search all items.</Empty>
            : f === 'bin' ? <Empty title="The bin is empty" icon="trash">Deleted items wait here until you empty it.</Empty>
              : <Empty title="Nothing here yet" icon="lock"><button type="button" className="btn primary sm" onClick={() => openCreate(f === 'type:3' ? 'card' : f === 'type:4' ? 'identity' : f === 'type:2' ? 'note' : 'login')}><Icon name="plus" size={14} />Add one</button></Empty>}
        </div>
      ) : (
        <ul className="vault-rows" role="listbox" aria-label={label}>
          {shown.map(it => (
            <li key={it.id}>
              <button type="button" role="option" aria-selected={it.id === id} className={`vault-row ${it.id === id ? 'active' : ''} ${it.error ? 'broken' : ''}`} onClick={() => navigate(`/item/${it.id}${qs}`)}>
                <ItemIcon it={it} />
                <span className="grow vr-text"><span className="vr-name ellipsis">{it.name}{it.favorite && <Icon name="star" size={12} className="vr-fav" />}</span><span className="vr-sub ellipsis">{subtitle(it)}</span></span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
  const detail = open ? <ItemView key={open.id} it={open} onBack={() => navigate(`/${qs}`)} mobile={mobile} />
    : id ? <div className="vault-detail"><Empty title="This item isn’t here" icon="search">It may have been deleted in another app.</Empty></div>
      : <div className="vault-detail vault-detail-empty"><Empty title="Pick an item" icon="lock">Or press <kbd>/</kbd> to find one, <kbd>n</kbd> for a new login.</Empty></div>
  return (
    <div className={`vault ${mobile ? (id ? 'show-detail' : 'show-list') : ''}`}>
      {(!mobile || !id) && listPane}
      {(!mobile || id) && detail}
      {renaming && folderId && <FolderModal folder={folders.find(x => x.id === folderId)} onClose={() => setRenaming(false)} onSaved={() => setRenaming(false)} />}
      {confirm === 'bin' && <Confirm title="Empty the bin?" confirmLabel="Delete for good" message={`${shown.length} items are deleted for good, in every app.`} onCancel={() => setConfirm(null)}
        onConfirm={async () => { setConfirm(null); try { await emptyBin(); toast('Bin emptied') } catch (e) { toast(errMsg(e), 'err') } }} />}
      {confirm === 'folder' && <Confirm title="Delete this folder?" confirmLabel="Delete folder" message="Its items stay in your vault, without a folder." onCancel={() => setConfirm(null)}
        onConfirm={async () => { setConfirm(null); try { await deleteFolder(folderId); navigate('/'); toast('Folder deleted') } catch (e) { toast(errMsg(e), 'err') } }} />}
    </div>
  )
}

export function ItemIcon({ it, size = 34 }: { it: Item; size?: number }) {
  const { settings } = useApp()
  const host = it.type === TYPE_LOGIN ? hostOf(it) : ''
  const [failed, setFailed] = useState(false)
  if (host && settings?.show_icons !== false && !failed && !/^(localhost|[\d.]+)$/.test(host)) {
    return <span className="item-ico img" style={{ width: size, height: size }}><img src={`/icons/${host}/icon.png`} alt="" width={size - 12} height={size - 12} loading="lazy" onError={() => setFailed(true)} onLoad={e => { if ((e.target as HTMLImageElement).naturalWidth <= 1) setFailed(true) }} /></span>
  }
  return <span className={`item-ico t${it.type}`} style={{ width: size, height: size }}><Icon name={TYPE_ICON[it.type] || 'lock'} size={Math.round(size * 0.5)} /></span>
}

// ---- one item ----

function ItemView({ it, onBack, mobile }: { it: Item; onBack: () => void; mobile: boolean }) {
  const { folders, setFavorite, deleteItem, restoreItem, archiveItem, moveItems } = useVault()
  const { toast } = useToast()
  const copy = useCopy()
  const [confirm, setConfirm] = useState<'delete' | 'forever' | null>(null)
  const [moving, setMoving] = useState(false)
  const [remind, setRemind] = useState(false)
  const [unlocked, setUnlocked] = useState(it.reprompt !== 1)
  const folder = folders.find(f => f.id === it.folderId)
  const run = async (fn: () => Promise<void>, msg: string) => { try { await fn(); toast(msg) } catch (e) { toast(errMsg(e), 'err') } }

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (e.metaKey || e.ctrlKey || e.altKey || t.closest('input, textarea, [contenteditable="true"]') || document.querySelector('.modal-backdrop, .palette-backdrop, .menu')) return
      if (e.key === 'u' && it.login?.username) { e.preventDefault(); copy(it.login.username, 'Username') }
      else if (e.key === 'p' && it.login?.password && unlocked) { e.preventDefault(); copy(it.login.password, 'Password', true) }
      else if (e.key === 't' && it.login?.totp) { e.preventDefault(); const s = parseTotp(it.login.totp); if (s) totp(s).then(c => copy(c, 'Code', true)) }
      else if (e.key === 'e' && !it.deletedDate && !it.error) { e.preventDefault(); openEdit(it) }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [it, copy, unlocked])

  const more: MenuItem[] = it.deletedDate ? [
    { label: 'Restore', icon: 'rotate-ccw', onSelect: () => run(() => restoreItem(it), 'Restored') },
    { label: 'Delete for good', icon: 'trash', danger: true, onSelect: () => setConfirm('forever') },
  ] : [
    { label: 'Move to a folder…', icon: 'folder', onSelect: () => setMoving(true) },
    ...(it.type === TYPE_CARD && it.card && cardExpiry(it.card) ? [{ label: 'Remind me before it expires…', icon: 'bell', onSelect: () => setRemind(true) }] : []),
    { label: it.archivedDate ? 'Take out of the archive' : 'Archive', icon: 'archive', onSelect: () => run(() => archiveItem(it, !it.archivedDate), it.archivedDate ? 'Back in your vault' : 'Archived') },
    'sep',
    { label: 'Move to the bin', icon: 'trash', danger: true, onSelect: () => setConfirm('delete') },
  ]
  return (
    <article className="vault-detail" aria-label={it.name}>
      <header className="item-head">
        {mobile && <button type="button" className="btn ghost icon-only" onClick={onBack} aria-label="Back"><Icon name="chevron-left" size={18} /></button>}
        <ItemIcon it={it} size={44} />
        <div className="grow item-title">
          <h2 className="ellipsis">{it.name}</h2>
          <div className="muted small item-sub"><span>{TYPE_NAME[it.type] || 'Item'}</span>{folder && <><span>·</span><Icon name="folder" size={12} /><span>{folder.name}</span></>}{it.archivedDate && <span>· archived</span>}{it.deletedDate && <span>· in the bin</span>}</div>
        </div>
        {!it.deletedDate && !it.error && <>
          <button type="button" className={`btn ghost icon-only ${it.favorite ? 'fav-on' : ''}`} aria-pressed={it.favorite} aria-label={it.favorite ? 'Remove from favourites' : 'Add to favourites'} title={it.favorite ? 'Favourite' : 'Add to favourites'} onClick={() => run(() => setFavorite(it, !it.favorite), it.favorite ? 'Removed from favourites' : 'Added to favourites')}><Icon name="star" size={18} /></button>
          <button type="button" className="btn sm" onClick={() => openEdit(it)} title="Edit (e)"><Icon name="edit" size={14} />Edit</button>
        </>}
        <MenuButton label="More" items={more} align="right"><Icon name="more" size={18} /></MenuButton>
      </header>
      {it.error ? <div className="callout danger"><Icon name="alert" size={15} /><span>{it.error} It’s still safe on the server; the Bitwarden apps may open it.</span></div>
        : !unlocked ? <Reprompt onOk={() => setUnlocked(true)} />
          : <ItemBody it={it} />}
      <footer className="item-meta muted small">
        <span>Updated {fmtDateTime(it.revisionDate)}</span>
        {it.creationDate && <span>Created {fmtDate(it.creationDate.slice(0, 10))}</span>}
        {it.login?.passwordRevisionDate && <span>Password changed {fmtDate(it.login.passwordRevisionDate.slice(0, 10))}</span>}
      </footer>
      {confirm === 'delete' && <Confirm title={`Move “${it.name}” to the bin?`} confirmLabel="Move to the bin" message="You can restore it from the bin." onCancel={() => setConfirm(null)} onConfirm={() => { setConfirm(null); run(() => deleteItem(it), 'Moved to the bin').then(onBack) }} />}
      {confirm === 'forever' && <Confirm title={`Delete “${it.name}” for good?`} confirmLabel="Delete for good" message="It’s gone from every app; this can’t be undone." onCancel={() => setConfirm(null)} onConfirm={() => { setConfirm(null); run(() => deleteItem(it, true), 'Deleted').then(onBack) }} />}
      {moving && <MoveModal it={it} onClose={() => setMoving(false)} onMove={async fid => { setMoving(false); await run(() => moveItems([it.id], fid), 'Moved') }} />}
      {remind && <RemindModal it={it} onClose={() => setRemind(false)} />}
    </article>
  )
}

function Reprompt({ onOk }: { onOk: () => void }) {
  const { session, status } = useVault()
  const [pw, setPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const check = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session || !status?.kdf) return
    setBusy(true); setErr('')
    try {
      const hash = await masterPasswordHash(await masterKey(pw, status.email, status.kdf), pw)
      await session.call('POST', '/accounts/verify-password', { masterPasswordHash: hash })
      onOk()
    } catch { setErr('That master password isn’t right.') } finally { setBusy(false) }
  }
  return (
    <form className="reprompt" onSubmit={check}>
      <Icon name="shield" size={20} />
      <div className="grow"><b>This item asks for your master password</b><p className="muted small">Enter it to see and copy what’s inside.</p>
        <div className="row"><input type="password" value={pw} onChange={e => setPw(e.target.value)} autoFocus autoComplete="current-password" /><button className="btn primary" disabled={busy || !pw}>Show</button></div>
        {err && <p className="small bad">{err}</p>}
      </div>
    </form>
  )
}

function ItemBody({ it }: { it: Item }) {
  return (
    <div className="item-body">
      {it.type === TYPE_LOGIN && it.login && <LoginFields it={it} />}
      {it.type === TYPE_CARD && it.card && <section className="fields">
        <Row label="Cardholder" value={it.card.cardholderName} />
        <Row label="Number" value={cardDigits(it.card.number)} secret mono display={groupCard(it.card.number)} />
        <Row label="Brand" value={it.card.brand} copy={false} />
        <Row label="Expires" value={it.card.expMonth || it.card.expYear ? `${it.card.expMonth.padStart(2, '0')} / ${it.card.expYear}` : ''} copy={false} extra={<Expiry it={it} />} />
        <Row label="Security code" value={it.card.code} secret mono />
      </section>}
      {it.type === TYPE_IDENTITY && it.identity && <IdentityFields it={it} />}
      {it.type === TYPE_SSH && it.sshKey && <section className="fields">
        <Row label="Public key" value={it.sshKey.publicKey} mono wrap />
        <Row label="Fingerprint" value={it.sshKey.keyFingerprint} mono />
        <Row label="Private key" value={it.sshKey.privateKey} secret mono wrap />
      </section>}
      {it.fields.length > 0 && <section className="fields"><h3 className="fields-h">Custom fields</h3>
        {it.fields.map((f, i) => f.type === 2 ? <Row key={i} label={f.name} value={f.value === 'true' ? 'Yes' : 'No'} copy={false} />
          : f.type === 3 ? <Row key={i} label={f.name} value="Linked to another field" copy={false} />
            : <Row key={i} label={f.name} value={f.value} secret={f.type === 1} />)}
      </section>}
      {it.notes && <section className="fields"><h3 className="fields-h">{it.type === TYPE_NOTE ? 'Note' : 'Notes'}</h3><Row label="" value={it.notes} wrap note /></section>}
      {it.history.length > 0 && <History it={it} />}
    </div>
  )
}

function LoginFields({ it }: { it: Item }) {
  const l = it.login!
  const st = l.password ? strength(l.password) : null
  return (
    <section className="fields">
      <Row label="Username" value={l.username} />
      <Row label="Password" value={l.password} secret mono badge={st && <span className={`badge s${st.score}`} title={`About ${st.bits} bits`}>{st.label}</span>} />
      {l.totp && <TotpRow secret={l.totp} />}
      {l.passkeys > 0 && <Row label="Passkey" value={`Saved (${l.passkeys})`} copy={false} />}
      {l.uris.map((u, i) => <UriRow key={i} uri={u.uri} first={i === 0} />)}
    </section>
  )
}

function UriRow({ uri, first }: { uri: string; first: boolean }) {
  const copy = useCopy()
  const href = /^https?:\/\//i.test(uri) ? uri : /^[\w-]+(\.[\w-]+)+/.test(uri) ? 'https://' + uri : ''
  return (
    <div className="frow">
      <span className="frow-l">{first ? 'Website' : ''}</span>
      <span className="frow-v ellipsis">{href ? <a href={href} target="_blank" rel="noreferrer noopener">{uri}</a> : uri}</span>
      <span className="frow-a">
        {href && <a className="btn ghost icon-only sm" href={href} target="_blank" rel="noreferrer noopener" aria-label="Open" title="Open"><Icon name="external" size={15} /></a>}
        <button type="button" className="btn ghost icon-only sm" aria-label="Copy" title="Copy" onClick={() => copy(uri, 'Address')}><Icon name="copy" size={15} /></button>
      </span>
    </div>
  )
}

function TotpRow({ secret }: { secret: string }) {
  const copy = useCopy()
  const spec = useMemo(() => parseTotp(secret), [secret])
  const [code, setCode] = useState('')
  const [left, setLeft] = useState(30)
  useEffect(() => {
    if (!spec) return
    let alive = true
    const tick = async () => {
      const now = Date.now()
      const l = spec.period - Math.floor(now / 1000) % spec.period
      try { const c = await totp(spec, now); if (alive) { setCode(c); setLeft(l) } } catch { if (alive) setCode('') }
    }
    tick()
    const t = setInterval(tick, 1000)
    return () => { alive = false; clearInterval(t) }
  }, [spec])
  if (!spec || !code) return <Row label="Authenticator key" value={secret} secret mono />
  const r = 8, c = 2 * Math.PI * r
  return (
    <div className="frow">
      <span className="frow-l">Code</span>
      <span className="frow-v mono totp">{code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code}
        <svg width={22} height={22} viewBox="0 0 22 22" className={`totp-ring ${left <= 5 ? 'low' : ''}`} aria-label={`${left} seconds left`}><circle cx={11} cy={11} r={r} className="totp-bg" /><circle cx={11} cy={11} r={r} className="totp-fg" strokeDasharray={`${(c * left) / spec.period} ${c}`} transform="rotate(-90 11 11)" /></svg>
        <span className="muted small tnum">{left}s</span>
      </span>
      <span className="frow-a"><button type="button" className="btn ghost icon-only sm" aria-label="Copy the code" title="Copy (t)" onClick={() => copy(code, 'Code', true)}><Icon name="copy" size={15} /></button></span>
    </div>
  )
}

function Row({ label, value, secret, mono, wrap, note, copy: canCopy = true, display, badge, extra }: { label: string; value: string; secret?: boolean; mono?: boolean; wrap?: boolean; note?: boolean; copy?: boolean; display?: string; badge?: React.ReactNode; extra?: React.ReactNode }) {
  const copy = useCopy()
  const [show, setShow] = useState(false)
  if (!value) return null
  const text = secret && !show ? '•'.repeat(Math.min(16, Math.max(8, value.length))) : display || value
  return (
    <div className={`frow ${note ? 'note' : ''}`}>
      {label !== '' && <span className="frow-l">{label}</span>}
      <span className={`frow-v ${mono ? 'mono' : ''} ${wrap || note ? 'wrap' : 'ellipsis'}`}>{text}{badge && <> {badge}</>}{extra}</span>
      <span className="frow-a">
        {secret && <button type="button" className="btn ghost icon-only sm" aria-label={show ? 'Hide' : 'Show'} title={show ? 'Hide' : 'Show'} onClick={() => setShow(s => !s)}><Icon name={show ? 'eye-off' : 'eye'} size={15} /></button>}
        {canCopy && <button type="button" className="btn ghost icon-only sm" aria-label={`Copy ${label || 'text'}`} title="Copy" onClick={() => copy(value, label || 'Text', !!secret)}><Icon name="copy" size={15} /></button>}
      </span>
    </div>
  )
}

const ID_GROUPS: [string, [keyof NonNullable<Item['identity']>, string][]][] = [
  ['Personal', [['title', 'Title'], ['firstName', 'First name'], ['middleName', 'Middle name'], ['lastName', 'Last name'], ['company', 'Company'], ['username', 'Username']]],
  ['Contact', [['email', 'Email'], ['phone', 'Phone']]],
  ['Address', [['address1', 'Address'], ['address2', ''], ['address3', ''], ['city', 'City'], ['state', 'State or region'], ['postalCode', 'Postcode'], ['country', 'Country']]],
  ['Documents', [['passportNumber', 'Passport'], ['licenseNumber', 'Driving licence'], ['ssn', 'National ID / SSN']]],
]

function IdentityFields({ it }: { it: Item }) {
  const id = it.identity!
  return <>{ID_GROUPS.filter(([, fs]) => fs.some(([k]) => id[k])).map(([g, fs]) => (
    <section key={g} className="fields"><h3 className="fields-h">{g}</h3>{fs.map(([k, l]) => <Row key={k} label={l} value={id[k]} secret={k === 'ssn'} />)}</section>
  ))}</>
}

function History({ it }: { it: Item }) {
  const [open, setOpen] = useState(false)
  return (
    <section className="fields">
      <button type="button" className="fields-h linkish" onClick={() => setOpen(o => !o)} aria-expanded={open}><Icon name={open ? 'chevron-down' : 'chevron-right'} size={14} />Earlier passwords ({it.history.length})</button>
      {open && it.history.map((h, i) => <Row key={i} label={fmtDate(h.lastUsedDate.slice(0, 10))} value={h.password} secret mono />)}
    </section>
  )
}

/** Just the digits of a card number (what a payment form wants), or the text as it is if it isn't one. */
function cardDigits(n: string): string {
  const d = n.replace(/[\s-]/g, '')
  return /^\d+$/.test(d) ? d : n
}

/** A card number in its groups: 4-6-5 for American Express, otherwise fours. */
function groupCard(n: string): string {
  const d = cardDigits(n)
  if (!/^\d+$/.test(d)) return n
  if (d.length === 15 && /^3[47]/.test(d)) return `${d.slice(0, 4)} ${d.slice(4, 10)} ${d.slice(10)}`
  return d.replace(/(\d{4})(?=\d)/g, '$1 ')
}

function Expiry({ it }: { it: Item }) {
  const end = it.card ? cardExpiry(it.card) : ''
  if (!end) return null
  const days = Math.ceil((Date.parse(end) - Date.now()) / 86400000)
  if (days < 0) return <span className="badge s0">expired</span>
  if (days < 62) return <span className="badge s1">expires soon</span>
  return null
}

function MoveModal({ it, onClose, onMove }: { it: Item; onClose: () => void; onMove: (folderId: string | null) => void }) {
  const { folders } = useVault()
  const [f, setF] = useState(it.folderId || '')
  return (
    <Modal title="Move to a folder" onClose={onClose} size="sm" footer={<><button type="button" className="btn" onClick={onClose}>Cancel</button><button type="button" className="btn primary" onClick={() => onMove(f || null)}>Move</button></>}>
      <Field label="Folder"><Select value={f} onChange={setF} options={[{ value: '', label: 'No folder' }, ...folders.map(x => ({ value: x.id, label: x.name }))]} /></Field>
    </Modal>
  )
}

function RemindModal({ it, onClose }: { it: Item; onClose: () => void }) {
  const { settings } = useApp()
  const { toast } = useToast()
  const card = it.card!
  const [title, setTitle] = useState(`${card.brand || 'Card'} ${card.number ? '•••• ' + card.number.slice(-4) : ''}`.trim() + ' expires')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<{ open_url?: string } | null>(null)
  const coreOn = !!settings?.core_configured && settings.core_registered !== false
  const connected = settings?.renewals_mode !== 'off' && (settings?.renewals_configured || coreOn)
  const send = async () => {
    setBusy(true)
    try {
      const r = await api.post<{ open_url?: string }>(`${V1}/vault/reminders`, { cipher_id: it.id, title, kind: 'other', holder: card.cardholderName, number: card.number, expires_on: cardExpiry(card) })
      setDone(r); toast('Pocket Renewals will remind you')
    } catch (e) { toast(errMsg(e), 'err') } finally { setBusy(false) }
  }
  const { data: sent } = useAsyncReminders(it.id)
  return (
    <Modal title="Remind me before it expires" onClose={onClose} size="sm">
      {done ? <div className="stack"><div className="callout ok"><Icon name="check-circle" size={15} /><span>Added to Pocket Renewals.</span></div>{done.open_url && <a className="btn" href={done.open_url} target="_blank" rel="noreferrer">Open in Pocket Renewals</a>}</div>
        : <div className="stack">
          <p className="small">Pocket Renewals reminds you ahead of <b>{fmtDate(cardExpiry(card))}</b>. It gets only this title, the cardholder, the date and the last four digits — never the number or the code.</p>
          {sent && <p className="small muted">Already sent on {fmtDate(sent.created_at.slice(0, 10))}; sending again updates it.</p>}
          <Field label="Title"><input value={title} onChange={e => setTitle(e.target.value)} maxLength={120} /></Field>
          {!connected && <div className="callout"><Icon name="info" size={15} /><span>Connect Pocket Renewals first (Settings → Connected apps).{!coreOn && <CoreHint />}</span></div>}
          <div className="form-actions"><button type="button" className="btn" onClick={onClose}>Cancel</button><button type="button" className="btn primary" disabled={busy || !connected || !title.trim()} onClick={send}>Send to Pocket Renewals</button></div>
        </div>}
    </Modal>
  )
}

function useAsyncReminders(id: string) {
  const [data, setData] = useState<Reminder | null>(null)
  useEffect(() => { api.get<Reminder[]>(`${V1}/vault/reminders`).then(rs => setData(rs.find(r => r.cipher_id === id) || null)).catch(() => {}) }, [id])
  return { data }
}

