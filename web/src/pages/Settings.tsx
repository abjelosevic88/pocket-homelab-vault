import React, { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import qrcode from 'qrcode-generator'
import { api, V1 } from '../lib/api'
import { useApp } from '../lib/app-context'
import { useVault } from '../lib/vault-context'
import type { APIToken, ConnMode, Settings as SettingsT, User } from '../lib/types'
import { DATE_FORMATS, TIME_FORMATS, fmtBytes, fmtDateTime, type DateFormat, type TimeFormat } from '../lib/format'
import { encryptBytes, masterKey, masterPasswordHash, stretch } from '../lib/crypto'
import { strength } from '../lib/generator'
import { exportEncrypted, exportPlain, importFile } from '../lib/transfer'
import { addPasskey, enablePasskeyUnlock, passkeysAvailable } from '../lib/passkey'
import { Avatar, Confirm, CoreHint, Field, Loading, Modal, Segmented, SettingRow, Switch, Tabs, errMsg, useAsync, useIsMobile, useToast } from '../components/ui'
import { Icon } from '../components/icons'
import { Select } from '../components/Select'
import { ShortcutsSheet } from '../components/ShortcutsSheet'
import { MoveFromVaultwarden } from '../components/LockScreen'

type TabId = 'general' | 'security' | 'notifications' | 'apps' | 'profile' | 'people' | 'tokens' | 'data' | 'about'

const TABS: { id: TabId; label: string; icon: string; sub: string }[] = [
  { id: 'general', label: 'General', icon: 'sliders', sub: 'Locking, the clipboard, website icons and how dates look.' },
  { id: 'security', label: 'Security', icon: 'shield', sub: 'Your master password, passkeys, two-step login and how your key is made.' },
  { id: 'notifications', label: 'Notifications', icon: 'bell', sub: 'Hear about new sign-ins, wrong tries and changes to your vault’s security.' },
  { id: 'apps', label: 'Connected apps', icon: 'layers', sub: 'Pocket Renewals (reminders before a card runs out) and what your other Pocket apps may know.' },
  { id: 'profile', label: 'Profile', icon: 'user', sub: 'Your name, email and the password for signing in to Pocket Vault.' },
  { id: 'people', label: 'People', icon: 'users', sub: 'Everyone who has an account on this box.' },
  { id: 'tokens', label: 'API & shortcuts', icon: 'key', sub: 'Personal tokens for scripts and Homepage widgets (they never reach your items).' },
  { id: 'data', label: 'Backup & data', icon: 'database', sub: 'Import from Bitwarden, a browser or Vaultwarden; export your vault; back up the database.' },
  { id: 'about', label: 'About', icon: 'info', sub: 'Version, numbers and the server.' },
]

export default function Settings() {
  const { tab: raw } = useParams()
  const navigate = useNavigate()
  const mobile = useIsMobile()
  const tab: TabId = TABS.find(t => t.id === raw)?.id || 'general'
  const current = TABS.find(t => t.id === tab)!
  const go = (id: TabId) => navigate(`/settings/${id}`, { replace: true })
  useEffect(() => { document.querySelector('.set-content')?.scrollTo({ top: 0 }) }, [tab])
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape' && !document.querySelector('.modal-backdrop, .menu, .sel-pop')) navigate('/') }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [navigate])
  return (
    <div className="set-page">
      <header className="set-header">
        <button type="button" className="btn ghost icon-only" aria-label="Back" title="Back (esc)" onClick={() => navigate('/')}><Icon name="chevron-left" size={18} /></button>
        <img src="/favicon.svg" alt="" width={24} height={24} className="set-logo" />
        <h1>Settings</h1>
        <span style={{ flex: 1 }} />
      </header>
      {mobile && <div className="set-tabs-mobile"><Tabs tabs={TABS.map(t => ({ id: t.id, label: t.label, icon: t.icon }))} value={tab} onChange={go} /></div>}
      <div className="set-body">
        {!mobile && (
          <nav className="set-nav" aria-label="Settings sections">
            {TABS.map(t => (
              <button key={t.id} type="button" className={`set-nav-item ${t.id === tab ? 'active' : ''}`} aria-current={t.id === tab ? 'page' : undefined} onClick={() => go(t.id)}>
                <Icon name={t.icon} size={16} />{t.label}
              </button>
            ))}
          </nav>
        )}
        <main className="set-content">
          <div className="set-inner" key={tab}>
            <div className="set-title"><h2>{current.label}</h2><p>{current.sub}</p></div>
            {tab === 'general' && <General />}
            {tab === 'security' && <Security />}
            {tab === 'notifications' && <Notifications />}
            {tab === 'apps' && <Integrations />}
            {tab === 'profile' && <Profile />}
            {tab === 'people' && <Users />}
            {tab === 'tokens' && <Tokens />}
            {tab === 'data' && <Data />}
            {tab === 'about' && <About />}
          </div>
        </main>
      </div>
    </div>
  )
}

function Section({ title, sub, icon, actions, children }: { title: React.ReactNode; sub?: React.ReactNode; icon?: string; actions?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <section className="set-section">
      <div className="set-section-head">
        {icon && <span className="set-app-ico"><Icon name={icon} size={17} /></span>}
        <div className="grow"><h3>{title}</h3>{sub && <p>{sub}</p>}</div>
        {actions && <div className="row">{actions}</div>}
      </div>
      {children && <div className="set-section-body">{children}</div>}
    </section>
  )
}

function useSettingsForm() {
  const { settings, setSettings, user } = useApp()
  const { toast } = useToast()
  const [f, setF] = useState<SettingsT | null>(settings)
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (!f && settings) setF(settings) }, [settings]) // eslint-disable-line react-hooks/exhaustive-deps
  const save = async (patch?: Partial<SettingsT>) => {
    if (!f) return
    setBusy(true)
    try { const s = await api.put<SettingsT>(`${V1}/settings`, { ...f, ...patch }); setSettings(s); setF(s); toast('Saved') } catch (e) { toast((e as Error).message, 'err') } finally { setBusy(false) }
  }
  return { f, setF, save, busy, isAdmin: user?.role === 'admin' }
}

function useTester() {
  const [test, setTest] = useState<Record<string, string>>({})
  const run = async (which: string, url: string, key: string, extra: Record<string, string> = {}) => {
    setTest(t => ({ ...t, [which]: 'testing…' }))
    try { const r = await api.post<{ ok: boolean; message?: string; error?: string }>(`${V1}/integrations/test`, { which, url, key, ...extra }); setTest(t => ({ ...t, [which]: r.ok ? `✓ ${r.message}` : `✕ ${r.error}` })) } catch (e) { setTest(t => ({ ...t, [which]: `✕ ${(e as Error).message}` })) }
  }
  const status = (which: string) => <span className={`small ${test[which]?.startsWith('✓') ? 'ok' : test[which]?.startsWith('✕') ? 'bad' : 'muted'}`}>{test[which]}</span>
  return { run, status }
}


function General() {
  const { f, setF, save, busy, isAdmin } = useSettingsForm()
  if (!f) return <Loading />
  return (
    <div className="stack loose">
      <Section title="Locking" icon="lock">
        <SettingRow title="Lock after" help="Minutes without touching this page. A reload or a closed tab always locks.">
          <Select ariaLabel="Lock after" value={String(f.lock_minutes)} onChange={v => setF({ ...f, lock_minutes: Number(v) })}
            options={[1, 5, 15, 30, 60, 240].map(m => ({ value: String(m), label: m < 60 ? `${m} minutes` : `${m / 60} hour${m > 60 ? 's' : ''}` })).concat([{ value: '0', label: 'Only when the tab closes' }])} />
        </SettingRow>
        <SettingRow title="Clear copied passwords" help="Wipes the clipboard after copying a password or a code (if it still holds it).">
          <Select ariaLabel="Clear the clipboard" value={String(f.clipboard_clear)} onChange={v => setF({ ...f, clipboard_clear: Number(v) })}
            options={[10, 20, 30, 60, 120, 300].map(s => ({ value: String(s), label: s < 60 ? `after ${s} seconds` : `after ${s / 60} minute${s > 60 ? 's' : ''}` })).concat([{ value: '0', label: 'Never' }])} />
        </SettingRow>
      </Section>
      <Section title="Looks" icon="palette">
        <SettingRow title="Website icons" help={f.icon_service === 'off' ? 'Switched off on this server (ICON_SERVICE=off).' : 'The site’s own icon next to each login. This server fetches it; the site learns only that someone on this server asked.'}>
          <Switch checked={f.show_icons} onChange={v => setF({ ...f, show_icons: v })} label="Website icons" disabled={f.icon_service === 'off'} />
        </SettingRow>
        <SettingRow title="Dates"><Select ariaLabel="Date format" value={f.date_format} onChange={v => setF({ ...f, date_format: v as DateFormat })} options={DATE_FORMATS.map(d => ({ value: d.id, label: d.label }))} /></SettingRow>
        <SettingRow title="Times"><Select ariaLabel="Time format" value={f.time_format} onChange={v => setF({ ...f, time_format: v as TimeFormat })} options={TIME_FORMATS.map(d => ({ value: d.id, label: d.label }))} /></SettingRow>
        {isAdmin && <SettingRow title="Name of this app" help="Shown in the sidebar and the browser tab, for everyone."><input value={f.title} onChange={e => setF({ ...f, title: e.target.value })} /></SettingRow>}
      </Section>
      <div className="row"><button type="button" className="btn primary" onClick={() => save()} disabled={busy}>Save changes</button></div>
    </div>
  )
}

/** The master password hash, worked out here from what was typed. */
async function hashOf(pw: string, email: string, kdf: { type: number; iterations: number; memory?: number | null; parallelism?: number | null }) {
  return masterPasswordHash(await masterKey(pw, email, kdf), pw)
}

function NeedUnlock() {
  return <div className="callout"><Icon name="lock" size={15} /><span>Unlock your vault first: these changes are made with your keys, here in the browser. <Link to="/">Go to the vault</Link></span></div>
}

function Security() {
  const { state, status } = useVault()
  if (!status) return <Loading />
  if (!status.has_vault) return <div className="callout"><Icon name="info" size={15} /><span>You don’t have a vault yet. <Link to="/">Set it up</Link>.</span></div>
  return (
    <div className="stack loose">
      {state !== 'unlocked' && <NeedUnlock />}
      <MasterPassword disabled={state !== 'unlocked'} />
      <Passkeys disabled={state !== 'unlocked'} />
      <TwoStep disabled={state !== 'unlocked'} />
      <Section title="How your key is made" icon="key" sub="The master password becomes your key with a deliberately slow function, so guessing is slow too.">
        <dl className="set-dl">
          <div><dt>Function</dt><dd>{status.kdf?.type === 1 ? `Argon2id, ${status.kdf.memory} MB, ${status.kdf.parallelism} threads` : 'PBKDF2-SHA256'}</dd></div>
          <div><dt>Iterations</dt><dd>{status.kdf?.iterations.toLocaleString()}</dd></div>
          <div><dt>Salt</dt><dd>your email, <code>{status.email}</code></dd></div>
        </dl>
        <p className="muted small mt">To switch to Argon2id, use the Bitwarden web vault or desktop app (Settings → Security → Keys); this server accepts the change.</p>
      </Section>
      <DeleteVault disabled={state !== 'unlocked'} />
    </div>
  )
}

function MasterPassword({ disabled }: { disabled: boolean }) {
  const { status, session, lock } = useVault()
  const { toast } = useToast()
  const [f, setF] = useState({ cur: '', pw: '', pw2: '', hint: status?.hint || '' })
  const [busy, setBusy] = useState(false)
  const st = strength(f.pw)
  const ok = f.cur && f.pw.length >= 12 && f.pw === f.pw2 && st.score >= 2
  const change = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!ok || !session || !status?.kdf) return
    setBusy(true)
    try {
      const old = await hashOf(f.cur, status.email, status.kdf)
      const mk = await masterKey(f.pw, status.email, status.kdf)
      const key = await encryptBytes(session.key.raw, await stretch(mk))
      await session.call('POST', '/accounts/password', { masterPasswordHash: old, newMasterPasswordHash: await masterPasswordHash(mk, f.pw), key, masterPasswordHint: f.hint })
      toast('Master password changed. Every app needs the new one.')
      lock()
    } catch (err) { toast(errMsg(err).replace('Invalid password', 'The current master password isn’t right.'), 'err') } finally { setBusy(false) }
  }
  return (
    <Section title="Master password" icon="key" sub="Changing it signs every app out; they ask for the new one. Your items stay as they are.">
      <form onSubmit={change} className="stack">
        <Field label="Current master password"><input type="password" value={f.cur} onChange={e => setF({ ...f, cur: e.target.value })} autoComplete="current-password" disabled={disabled} /></Field>
        <div className="two-col tight">
          <Field label="New master password" help="At least 12 characters."><input type="password" value={f.pw} onChange={e => setF({ ...f, pw: e.target.value })} autoComplete="new-password" disabled={disabled} /></Field>
          <Field label="Type it again"><input type="password" value={f.pw2} onChange={e => setF({ ...f, pw2: e.target.value })} autoComplete="new-password" disabled={disabled} /></Field>
        </div>
        {f.pw && <div className={`meter s${st.score}`}><span style={{ width: `${(st.score + 1) * 20}%` }} /><b>{st.label}</b></div>}
        <Field label="Hint (optional)"><input value={f.hint} onChange={e => setF({ ...f, hint: e.target.value })} maxLength={200} disabled={disabled} /></Field>
        <div className="row"><button className="btn primary" disabled={disabled || !ok || busy}>{busy ? 'Changing…' : 'Change master password'}</button></div>
      </form>
    </Section>
  )
}

interface PasskeyRow { id: string; name: string; prfStatus: number; creationDate: string; lastUsedDate: string | null }

function guessPasskeyName(): string {
  const ua = navigator.userAgent
  if (/iPhone/.test(ua)) return 'iPhone'
  if (/iPad/.test(ua)) return 'iPad'
  if (/Android/.test(ua)) return 'Android phone'
  if (/Mac OS X/.test(ua)) return 'Mac'
  if (/Windows/.test(ua)) return 'Windows Hello'
  return 'Passkey'
}

function Passkeys({ disabled }: { disabled: boolean }) {
  const { status, session, reloadStatus } = useVault()
  const { toast } = useToast()
  const [list, setList] = useState<PasskeyRow[] | null>(null)
  const [adding, setAdding] = useState(false)
  const [name, setName] = useState(guessPasskeyName)
  const [pw, setPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [removing, setRemoving] = useState<PasskeyRow | null>(null)
  const [unlocking, setUnlocking] = useState(false)
  const supported = passkeysAvailable()
  const load = async () => { if (session) setList((await session.call<{ data: PasskeyRow[] }>('GET', '/webauthn')).data) }
  useEffect(() => { load().catch(() => setList([])) }, [session]) // eslint-disable-line react-hooks/exhaustive-deps
  const hash = async () => { if (!status?.kdf) throw new Error('No vault'); return hashOf(pw, status.email, status.kdf) }
  const wrongPw = (e: unknown) => errMsg(e).replace('Invalid password', 'That master password isn’t right.')
  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session || !pw) return
    setBusy(true)
    try {
      const r = await addPasskey(session.call.bind(session), session.key, await hash(), name.trim() || 'Passkey')
      toast(r.unlocks ? 'Passkey added. It signs in and unlocks your vault.' : 'Passkey added for signing in. This browser or key can’t unlock with it, so the master password is still asked.', 'ok')
      setAdding(false); setPw(''); setName(guessPasskeyName()); await load(); await reloadStatus()
    } catch (e) { toast(wrongPw(e), 'err') } finally { setBusy(false) }
  }
  const remove = async () => {
    if (!session || !removing) return
    setBusy(true)
    try { await session.call('POST', `/webauthn/${removing.id}/delete`, { masterPasswordHash: await hash() }); toast('Passkey removed'); setRemoving(null); setPw(''); await load(); await reloadStatus() }
    catch (e) { toast(wrongPw(e), 'err') } finally { setBusy(false) }
  }
  const turnOnUnlock = async () => {
    if (!session) return
    setBusy(true)
    try { await enablePasskeyUnlock(session.call.bind(session), session.key, await hash()); toast('That passkey now unlocks your vault too'); setUnlocking(false); setPw(''); await load(); await reloadStatus() }
    catch (e) { toast(wrongPw(e), 'err') } finally { setBusy(false) }
  }
  const n = list?.length || 0
  return (
    <Section title="Passkeys" icon="fingerprint" actions={n > 0 ? <span className="badge ok">{n}</span> : <span className="badge">none</span>}
      sub="Unlock with Touch ID, Face ID, Windows Hello, your phone or a security key instead of typing the master password. The passkey opens your key here in the browser; the server still can’t read anything. Keep your master password: it’s still the way in for the Bitwarden apps and if a passkey is lost.">
      {!supported && <div className="callout warn mb"><Icon name="info" size={15} /><span>This browser can’t use passkeys.</span></div>}
      {list && list.length > 0 && <ul className="pk-list">
        {list.map(p => <li key={p.id}>
          <Icon name="fingerprint" size={18} />
          <div className="grow">
            <b>{p.name}</b>
            <div className="muted small">{p.prfStatus === 0 ? 'Signs in and unlocks' : 'Signs in only — the master password is still asked'} · added {fmtDateTime(p.creationDate)}{p.lastUsedDate ? ` · last used ${fmtDateTime(p.lastUsedDate)}` : ''}</div>
          </div>
          <button type="button" className="btn sm danger-ghost" disabled={disabled} onClick={() => { setRemoving(p); setPw('') }}>Remove</button>
        </li>)}
      </ul>}
      {list && list.some(p => p.prfStatus !== 0) && !unlocking && <button type="button" className="linkish small mb" disabled={disabled} onClick={() => { setUnlocking(true); setPw('') }}>Let a sign-in-only passkey unlock too…</button>}
      {unlocking ? (
        <div className="stack">
          <Field label="Master password" help="Then pick the passkey when the browser asks."><input type="password" value={pw} onChange={e => setPw(e.target.value)} autoFocus autoComplete="current-password" /></Field>
          <div className="row"><button type="button" className="btn" onClick={() => setUnlocking(false)}>Cancel</button><button type="button" className="btn primary" disabled={!pw || busy} onClick={turnOnUnlock}>{busy ? 'Waiting for your passkey…' : 'Continue'}</button></div>
        </div>
      ) : adding ? (
        <form onSubmit={add} className="stack">
          <div className="two-col tight">
            <Field label="Name" help="So you can tell them apart."><input value={name} onChange={e => setName(e.target.value)} maxLength={50} /></Field>
            <Field label="Master password" help="Needed to add one."><input type="password" value={pw} onChange={e => setPw(e.target.value)} autoFocus autoComplete="current-password" /></Field>
          </div>
          <p className="muted small">The browser asks once to make the passkey and may ask once more to set up unlocking.</p>
          <div className="row"><button type="button" className="btn" onClick={() => { setAdding(false); setPw('') }}>Cancel</button><button className="btn primary" disabled={!pw || busy}>{busy ? <><span className="spinner" />Waiting for your passkey…</> : 'Add passkey'}</button></div>
        </form>
      ) : <div className="row"><button type="button" className="btn primary" disabled={disabled || !supported || n >= 10} onClick={() => setAdding(true)}><Icon name="plus" size={15} />Add a passkey</button></div>}
      {removing && <Modal title={`Remove “${removing.name}”?`} onClose={() => setRemoving(null)} size="sm">
        <div className="stack">
          <p>It won’t sign in to your vault any more. Also delete it from the device or password manager that holds it, if you like.</p>
          <Field label="Master password"><input type="password" value={pw} onChange={e => setPw(e.target.value)} autoFocus autoComplete="current-password" /></Field>
          <div className="form-actions"><button type="button" className="btn" onClick={() => setRemoving(null)}>Cancel</button><button type="button" className="btn danger" disabled={!pw || busy} onClick={remove}>Remove</button></div>
        </div>
      </Modal>}
    </Section>
  )
}

function TwoStep({ disabled }: { disabled: boolean }) {
  const { status, session, reloadStatus } = useVault()
  const { toast } = useToast()
  const [pw, setPw] = useState('')
  const [setup, setSetup] = useState<{ key: string; hash: string } | null>(null)
  const [code, setCode] = useState('')
  const [recovery, setRecovery] = useState('')
  const [busy, setBusy] = useState(false)
  const on = !!status?.two_factor
  const withHash = async () => { if (!status?.kdf) throw new Error('No vault'); return hashOf(pw, status.email, status.kdf) }
  const start = async () => {
    if (!session) return
    setBusy(true)
    try { const hash = await withHash(); const r = await session.call<{ key: string }>('POST', '/two-factor/get-authenticator', { masterPasswordHash: hash }); setSetup({ key: r.key, hash }) }
    catch (e) { toast(errMsg(e).replace('Invalid password', 'That master password isn’t right.'), 'err') } finally { setBusy(false) }
  }
  const enable = async () => {
    if (!session || !setup) return
    setBusy(true)
    try {
      await session.call('POST', '/two-factor/authenticator', { key: setup.key, token: code.replace(/\s/g, ''), masterPasswordHash: setup.hash })
      const r = await session.call<{ code: string }>('POST', '/two-factor/get-recover', { masterPasswordHash: setup.hash })
      setRecovery(r.code); setSetup(null); setCode(''); setPw(''); await reloadStatus(); toast('Two-step login is on')
    } catch (e) { toast(errMsg(e), 'err') } finally { setBusy(false) }
  }
  const disable = async () => {
    if (!session) return
    setBusy(true)
    try { await session.call('POST', '/two-factor/disable', { masterPasswordHash: await withHash(), type: 0 }); setPw(''); await reloadStatus(); toast('Two-step login is off') }
    catch (e) { toast(errMsg(e).replace('Invalid password', 'That master password isn’t right.'), 'err') } finally { setBusy(false) }
  }
  const showRecovery = async () => {
    if (!session) return
    try { const r = await session.call<{ code: string }>('POST', '/two-factor/get-recover', { masterPasswordHash: await withHash() }); setRecovery(r.code) } catch (e) { toast(errMsg(e).replace('Invalid password', 'That master password isn’t right.'), 'err') }
  }
  const uri = setup && status ? `otpauth://totp/${encodeURIComponent('Pocket Vault:' + status.email)}?secret=${setup.key}&issuer=${encodeURIComponent('Pocket Vault')}` : ''
  return (
    <Section title="Two-step login" icon="shield-check" actions={<span className={`badge ${on ? 'ok' : 'warn'}`}>{on ? 'on' : 'off'}</span>}
      sub="Besides the master password, signing in asks for a code from an authenticator app on your phone (Google Authenticator, Aegis, 2FAS, 1Password…). Strongly recommended.">
      {recovery && <div className="set-fresh mb"><div className="row"><Icon name="check-circle" size={16} /><b>Your recovery code — write it down, keep it offline.</b></div><pre className="mono">{recovery.replace(/(.{4})/g, '$1 ').trim()}</pre><p className="small muted">It signs you in without your phone once, and turns two-step login off.</p></div>}
      {setup ? (
        <div className="tf-setup">
          <div className="tf-qr" dangerouslySetInnerHTML={{ __html: qrSvg(uri) }} aria-label="QR code for your authenticator app" />
          <div className="stack grow">
            <p className="small">Scan this with your authenticator app, or type the key:</p>
            <code className="mono tf-key">{setup.key.replace(/(.{4})/g, '$1 ').trim()}</code>
            <Field label="The 6-digit code it shows"><input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" autoFocus /></Field>
            <div className="row"><button type="button" className="btn" onClick={() => setSetup(null)}>Cancel</button><button type="button" className="btn primary" onClick={enable} disabled={busy || code.replace(/\s/g, '').length !== 6}>Turn on</button></div>
          </div>
        </div>
      ) : (
        <div className="stack">
          <Field label="Master password" help={on ? 'Needed to turn it off or to show the recovery code.' : 'Needed to set it up.'}><input type="password" value={pw} onChange={e => setPw(e.target.value)} autoComplete="current-password" disabled={disabled} /></Field>
          <div className="row wrap">
            {on ? <><button type="button" className="btn" onClick={showRecovery} disabled={disabled || !pw}>Show the recovery code</button><button type="button" className="btn danger" onClick={disable} disabled={disabled || !pw || busy}>Turn off</button></>
              : <button type="button" className="btn primary" onClick={start} disabled={disabled || !pw || busy}><Icon name="qr" size={15} />Set up an authenticator app</button>}
          </div>
        </div>
      )}
    </Section>
  )
}

function qrSvg(text: string): string {
  const q = qrcode(0, 'M')
  q.addData(text)
  q.make()
  return q.createSvgTag({ cellSize: 4, margin: 2, scalable: true })
}

function DeleteVault({ disabled }: { disabled: boolean }) {
  const { status, lock, reloadStatus } = useVault()
  const { toast } = useToast()
  const [open, setOpen] = useState(false)
  const [pw, setPw] = useState('')
  const [busy, setBusy] = useState(false)
  const del = async () => {
    if (!status?.kdf) return
    setBusy(true)
    try { await fetch(`${V1}/vault`, { method: 'DELETE', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ master_password_hash: await hashOf(pw, status.email, status.kdf) }) }).then(async r => { if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText) })
      lock(); await reloadStatus(); toast('Your vault was deleted') }
    catch (e) { toast(errMsg(e), 'err') } finally { setBusy(false) }
  }
  return (
    <Section title="Delete your vault" icon="trash" sub="Every item, folder and signed-in app, for good. Your Pocket Vault account stays.">
      <button type="button" className="btn danger" disabled={disabled} onClick={() => setOpen(true)}>Delete my vault…</button>
      {open && <Modal title="Delete your vault?" onClose={() => setOpen(false)} size="sm">
        <div className="stack">
          <p>This can’t be undone. Export it first (Backup &amp; data) if you might want it back.</p>
          <Field label="Master password"><input type="password" value={pw} onChange={e => setPw(e.target.value)} autoFocus autoComplete="current-password" /></Field>
          <div className="form-actions"><button type="button" className="btn" onClick={() => setOpen(false)}>Cancel</button><button type="button" className="btn danger" disabled={!pw || busy} onClick={del}>Delete for good</button></div>
        </div>
      </Modal>}
    </Section>
  )
}

function Notifications() {
  const { f, setF, save, busy } = useSettingsForm()
  const { run, status } = useTester()
  if (!f) return <Loading />
  return (
    <div className="stack loose">
      <Section title="Where they go" icon="bell" actions={<span className={`badge ${f.notify_configured ? 'ok' : ''}`}>{f.notify_configured ? 'on' : 'not set'}</span>}
        sub={<>A Pocket Alerts source or an Apprise gateway (<code>…/notify/&lt;key&gt;</code>), an ntfy topic URL, or any webhook that takes JSON.</>}>
        <SettingRow title="URL" stack><input value={f.notify_url} onChange={e => setF({ ...f, notify_url: e.target.value })} placeholder="http://apprise:8000/notify/vault" /></SettingRow>
        <SettingRow title="Format"><Segmented value={f.notify_format} onChange={v => setF({ ...f, notify_format: v })} options={[{ value: 'apprise', label: 'Apprise' }, { value: 'ntfy', label: 'ntfy' }, { value: 'json', label: 'JSON' }]} size="sm" /></SettingRow>
      </Section>
      <Section title="Tell me when" icon="shield">
        <SettingRow title="An app signs in on a new device" help="With the app, the device and the address."><Switch checked={f.notify_new_device} onChange={v => setF({ ...f, notify_new_device: v })} label="New device" /></SettingRow>
        <SettingRow title="Several wrong tries" help="Three wrong master passwords or codes in a row (at most once an hour)."><Switch checked={f.notify_failed} onChange={v => setF({ ...f, notify_failed: v })} label="Wrong tries" /></SettingRow>
        <SettingRow title="Security changes" help="Master password, two-step login or key settings changed."><Switch checked={f.notify_security} onChange={v => setF({ ...f, notify_security: v })} label="Security changes" /></SettingRow>
      </Section>
      <div className="row wrap">
        <button type="button" className="btn primary" onClick={() => save()} disabled={busy}>Save changes</button>
        <button type="button" className="btn" onClick={() => run('notify', f.notify_url, '', { format: f.notify_format })} disabled={!f.notify_url}><Icon name="mail" size={15} />Send a test</button>
        {status('notify')}
      </div>
    </div>
  )
}

function Integrations() {
  const { f, setF, save, busy } = useSettingsForm()
  const { run, status } = useTester()
  if (!f) return <Loading />
  const coreOn = f.core_configured && f.core_registered !== false
  const eff = (m: ConnMode): ConnMode => !coreOn && m === 'core' ? 'off' : m
  return (
    <div className="stack loose">
      <div className="callout info"><Icon name="info" size={15} /><div>Your other Pocket apps never see what’s in your vault — the server can’t read it either. What can cross: a reminder you send yourself, and the health numbers if you share them.{!coreOn && <CoreHint />}</div></div>
      <Section title="Pocket Renewals — remind me before it expires" icon="bell" actions={connBadge(eff(f.renewals_mode), f.renewals_via)}
        sub="On a card: More → Remind me before it expires. Only the title, the cardholder, the date and the last four digits are sent.">
        <Connection app="Pocket Renewals" mode={f.renewals_mode} via={f.renewals_via} detail={f.renewals_detail} core={coreOn} hasToken={!!f.renewals_token}
          onMode={m => save({ renewals_mode: m })} onDisconnect={() => save({ renewals_url: '', renewals_token: '' })}
          test={<><button type="button" className="btn sm" onClick={() => run('renewals', f.renewals_url, f.renewals_token)}>Test connection</button>{status('renewals')}</>}
          direct={<div className="two-col tight">
            <Field label="URL" help="Inside Docker use http://host.docker.internal:PORT or the service name."><input value={f.renewals_url} onChange={e => setF({ ...f, renewals_url: e.target.value })} placeholder="http://host.docker.internal:8230" /></Field>
            <Field label="API token" help="Pocket Renewals → Settings → API & shortcuts"><input value={f.renewals_token} onChange={e => setF({ ...f, renewals_token: e.target.value })} autoComplete="off" /></Field>
          </div>} />
      </Section>
      <Section title="Share the health numbers" icon="shield-check" sub="Pocket Day, Pocket AI and your dashboards can then say “3 weak passwords, 2 used twice”. Only counts and a score — never a name, a site or a password. Updated when you open Health.">
        <SettingRow title="Share them" help={coreOn ? 'Other apps also need the vault:read link switched on in Pocket Core → Links.' : 'Needs Pocket Core for other apps to read them.'}>
          <Switch checked={f.share_health} onChange={v => save({ share_health: v })} label="Share health numbers" disabled={!coreOn && !f.share_health} />
        </SettingRow>
      </Section>
      <Section title="What other Pocket apps may read" icon="layers" sub="Offered through Pocket Core, off until you switch it on there.">
        <dl className="set-dl">
          <div><dt>vault:read</dt><dd className="muted">How many items, which apps are signed in, whether two-step login is on, recent sign-ins, and the shared health numbers.</dd></div>
          <div><dt>Events</dt><dd className="muted"><code>vault.device_signed_in</code>, <code>vault.signin_failed</code>, <code>vault.security_changed</code> — for Pocket Alerts and automations.</dd></div>
        </dl>
      </Section>
      <div className="row"><button type="button" className="btn primary" onClick={() => save()} disabled={busy}>Save changes</button></div>
    </div>
  )
}

function Tokens() {
  const { toast } = useToast()
  const { settings } = useApp()
  const { data, reload } = useAsync(() => api.get<APIToken[]>(`${V1}/tokens`), [])
  const [name, setName] = useState('')
  const [fresh, setFresh] = useState('')
  const [del, setDel] = useState<APIToken | null>(null)
  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    try { const r = await api.post<{ token: string }>(`${V1}/tokens`, { name: name || 'token' }); setFresh(r.token); setName(''); reload() } catch (e) { toast((e as Error).message, 'err') }
  }
  const base = settings?.base_url || window.location.origin
  return (
    <div className="stack loose">
      <Section title="Personal tokens" icon="key" sub={<>Use as <code>Authorization: Bearer &lt;token&gt;</code> for this app’s own API (<code>/api/v1</code>). A token can’t open your vault: that needs the master password.</>}>
        <form onSubmit={create} className="row mb"><input value={name} onChange={e => setName(e.target.value)} placeholder="Token name (e.g. Homepage)" /><button className="btn primary"><Icon name="plus" size={15} />Create</button></form>
        {fresh && <div className="set-fresh mb"><div className="row"><Icon name="check-circle" size={16} /><b>Copy it now — it is shown once.</b></div><pre className="mono">{fresh}</pre></div>}
        {data && data.length > 0 ? (
          <table className="table compact">
            <thead><tr><th>Name</th><th>Prefix</th><th>Last used</th><th>Created</th><th /></tr></thead>
            <tbody>{data.map(t => <tr key={t.id}><td>{t.name}</td><td className="mono">{t.prefix}…</td><td className="muted">{t.last_used_at ? fmtDateTime(t.last_used_at) : 'never'}</td><td className="muted">{fmtDateTime(t.created_at)}</td><td className="right"><button type="button" className="btn ghost sm danger-text" onClick={() => setDel(t)}>Revoke</button></td></tr>)}</tbody>
          </table>
        ) : <p className="muted">No tokens yet.</p>}
        {del && <Confirm confirmLabel="Revoke" title={`Revoke “${del.name}”?`} message="Anything using this token stops working immediately." onCancel={() => setDel(null)} onConfirm={async () => { await api.del(`${V1}/tokens/${del.id}`); setDel(null); reload() }} />}
      </Section>
      <Section title="Endpoints" icon="code" sub={<>At <code>{base}/api/v1</code>.</>}>
        <dl className="set-dl">
          <div><dt><code>GET /vault/overview</code></dt><dd className="muted">Counts, signed-in apps, two-step login and the shared health numbers — for Homepage or Pocket Day.</dd></div>
          <div><dt><code>GET /vault/activity</code></dt><dd className="muted">Sign-ins and security changes.</dd></div>
          <div><dt>Bitwarden API</dt><dd className="muted"><code>{base}/identity</code>, <code>{base}/api</code> and <code>{base}/notifications</code> — what the Bitwarden apps and <code>bw</code> use.</dd></div>
        </dl>
      </Section>
    </div>
  )
}

function Data() {
  const { toast } = useToast()
  const { user } = useApp()
  const vault = useVault()
  const [busy, setBusy] = useState('')
  const [plain, setPlain] = useState(false)
  const unlocked = vault.state === 'unlocked'
  const doImport = async (file: File) => {
    if (!vault.session) return
    setBusy('import')
    try { const n = await importFile(vault.session, file); await vault.sync(); toast(`Imported ${n.items} items${n.folders ? ` and ${n.folders} folders` : ''}`) } catch (e) { toast(errMsg(e), 'err') } finally { setBusy('') }
  }
  const doExport = async (kind: 'encrypted' | 'plain') => {
    if (!vault.session) return
    setBusy('export')
    try { if (kind === 'encrypted') await exportEncrypted(vault.session, vault.items, vault.folders); else await exportPlain(vault.items, vault.folders); setPlain(false) } catch (e) { toast(errMsg(e), 'err') } finally { setBusy('') }
  }
  return (
    <div className="stack loose">
      {!unlocked && <NeedUnlock />}
      <Section title="Import" icon="upload" sub="From a Bitwarden export (.json, plain or “account restricted” from this vault), a Bitwarden .csv, or a browser’s password export (Chrome, Edge, Firefox, Safari .csv). Everything is encrypted here before it is saved.">
        <label className={`btn ${!unlocked ? 'disabled' : ''}`} aria-disabled={!unlocked}><Icon name="upload" size={15} />{busy === 'import' ? 'Importing…' : 'Choose a file…'}<input type="file" accept=".json,.csv,application/json,text/csv" hidden disabled={!unlocked || !!busy} onChange={e => { const f = e.target.files?.[0]; e.target.value = ''; if (f) doImport(f) }} /></label>
        <p className="muted small mt">Delete the export file afterwards: it holds your passwords in the open.</p>
      </Section>
      <Section title="Export" icon="download" sub="A copy of your vault in Bitwarden’s format, which every Bitwarden app and most password managers can import.">
        <div className="row wrap">
          <button type="button" className="btn" disabled={!unlocked || !!busy} onClick={() => doExport('encrypted')}><Icon name="lock" size={15} />Encrypted (.json)</button>
          <button type="button" className="btn" disabled={!unlocked || !!busy} onClick={() => setPlain(true)}><Icon name="file" size={15} />Readable (.json)</button>
        </div>
        <p className="muted small mt">Encrypted opens only with this vault’s key (in Bitwarden: Import → Bitwarden (json), signed in to this account). Readable is plain text — anyone with the file sees everything.</p>
      </Section>
      {user?.role === 'admin' && <Section title="Move from Vaultwarden" icon="arrow-left-right" sub="For an admin: bring every account over from a Vaultwarden server at once, apps staying signed in.">
        <MoveFromVaultwarden onDone={() => vault.reloadStatus()} />
      </Section>}
      {user?.role === 'admin' && <Section title="Database backup" icon="database" sub="The whole box, every account — admins only. Items stay encrypted with each person’s own key.">
        <p className="muted">A consistent copy of the SQLite database (<code>VACUUM INTO</code>). Restore by stopping the app and replacing <code>pocket-vault.db</code> in the data directory; keep <code>rsa_key.pem</code> with it.</p>
        <a className="btn primary" href={`${V1}/backup`}><Icon name="download" size={15} />Download database</a>
      </Section>}
      {plain && <Confirm title="Export everything as readable text?" confirmLabel="Export readable" message="The file holds every password in plain text. Keep it somewhere safe and delete it when you are done." onCancel={() => setPlain(false)} onConfirm={() => doExport('plain')} />}
    </div>
  )
}

function About() {
  const { data, error } = useAsync(() => api.get<Record<string, unknown>>(`${V1}/settings/system`), [])
  const { status } = useVault()
  const [keys, setKeys] = useState(false)
  if (error) return <div className="callout danger"><Icon name="alert" size={15} /><span>{error}</span></div>
  if (!data) return <Loading />
  const counts = (data.counts || {}) as Record<string, number>
  const core = (data.core || {}) as { configured?: boolean; registered?: boolean; url?: string; error?: string }
  const vc = status?.counts || {}
  const tiles: [string, number | undefined, string][] = [['Items', vc.items, 'lock'], ['Folders', vc.folders, 'folder'], ['Signed-in apps', status?.devices, 'smartphone'], ['In the bin', vc.bin, 'trash']]
  const rows: [string, React.ReactNode][] = [
    ['Version', <code key="v">{String(data.version)}</code>],
    ['Answers the apps as', <span key="b">Bitwarden server {String(data.bitwarden_version)}</span>],
    ['Live sync', `${String(data.live_apps)} apps connected now`],
    ['Website icons', String(data.icon_service)],
    ['Uptime', String(data.uptime)],
    ['Runtime', `${String(data.go)} · ${String(data.os)}/${String(data.arch)}`],
    ['Time zone', String(data.timezone)],
    ['Sign-in', String(data.auth_mode)],
    ['Pocket Core', core.configured ? (core.registered ? <span key="c" className="ok">connected · {core.url}</span> : <span key="c" className="bad">{core.error || 'not registered yet'}</span>) : <span key="c" className="muted">not configured</span>],
    ['Database', <span key="db"><code>{String(data.db_path)}</code> · {fmtBytes(Number(data.db_bytes))}</span>],
    ['People', `${counts.users ?? 0} accounts on this box`],
  ]
  return (
    <div className="stack loose">
      <div className="set-about-hero">
        <img src="/favicon.svg" alt="" width={48} height={48} />
        <div>
          <h3>Pocket Vault</h3>
          <p className="muted small">Your passwords, cards, notes and identities, encrypted on your own devices and kept on your own server. Works with the Bitwarden apps; has its own web vault, a generator, a health check, two-step login and activity. One Go binary, one SQLite file, one volume.</p>
        </div>
      </div>
      <div className="set-stats">
        {tiles.map(([label, n, icon]) => (
          <div key={label} className="set-stat"><Icon name={icon} size={16} /><span className="set-stat-n tnum">{(n ?? 0).toLocaleString()}</span><span className="set-stat-l">{label}</span></div>
        ))}
      </div>
      <Section title="This server">
        <dl className="set-dl">
          {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}
        </dl>
      </Section>
      <div className="row wrap">
        <button type="button" className="btn" onClick={() => setKeys(true)}><Icon name="keyboard" size={15} />Keyboard shortcuts</button>
        <Link className="btn" to="/apps"><Icon name="puzzle" size={15} />Bitwarden apps</Link>
        <a className="btn" href="https://github.com/abjelosevic88/pocket-homelab-vault" target="_blank" rel="noreferrer"><Icon name="external" size={15} />Project on GitHub</a>
      </div>
      <p className="muted small">Open source (MIT). Not affiliated with Bitwarden, Inc.; it speaks the same protocol as their apps, as Vaultwarden does. Passphrases use the EFF large wordlist (CC BY 3.0).</p>
      {keys && <ShortcutsSheet onClose={() => setKeys(false)} />}
    </div>
  )
}

function Connection({ app, mode: saved, via, detail, core, onMode, onDisconnect, hasToken, test, direct }: {
  app: string; mode: ConnMode; via: string; detail: string; core: boolean; onMode: (m: ConnMode) => void; onDisconnect: () => void
  hasToken: boolean; test: React.ReactNode; direct: React.ReactNode
}) {
  const [advanced, setAdvanced] = useState(saved === 'direct')
  const mode: ConnMode = !core && saved === 'core' ? 'off' : saved
  const ok = via !== '' && mode !== 'off'
  const showDirect = !core || mode === 'direct' || advanced
  const line = mode === 'off' ? `Off: Vault does not talk to ${app}.`
    : mode === 'core' ? (ok ? `Connected through Pocket Core, as you${detail ? ` (${detail})` : ''}. Nothing to fill in; switch it off for yourself in Pocket Core → Settings → Apps acting for me.` : `Not connected: ${detail}.`)
    : (ok ? `Direct connection with your own ${app} URL and token; use Test connection to check it.` : `Not connected: ${detail || 'add the URL and a token'}.`)
  return (
    <div className="conn-block">
      <div className="conn-mode">
        <Segmented size="sm" value={mode} onChange={m => onMode(m as ConnMode)} options={[
          { value: 'core', label: 'Pocket Core', title: core ? 'Through Pocket Core: per person, nothing to paste' : 'Needs Pocket Core: there is none on this box', disabled: !core },
          ...(showDirect ? [{ value: 'direct', label: 'Direct', title: 'Your own URL and API token' }] : []),
          { value: 'off', label: 'Off' },
        ]} />
        {!showDirect && <button type="button" className="conn-advanced" onClick={() => setAdvanced(true)}>Advanced: connect directly with a URL and key</button>}
      </div>
      <div className={`conn-status ${mode === 'off' ? '' : ok ? 'ok' : 'bad'}`}><span className="dot" />{line}</div>
      {mode === 'direct' && <>
        {direct}
        <div className="row wrap">{test}{hasToken && <button type="button" className="btn sm ghost danger-text" onClick={onDisconnect} title="Remove the saved URL and token">Disconnect</button>}</div>
      </>}
      {mode === 'core' && <div className="row wrap">{test}</div>}
    </div>
  )
}

const connBadge = (mode: ConnMode, via: string) => mode === 'off' ? <span className="badge">off</span>
  : via ? <span className="badge ok">{via === 'core' ? 'Pocket Core' : 'direct'}</span>
  : <span className="badge warn">not connected</span>

function Users() {
  const { user, users, reloadMeta, status } = useApp()
  const { toast } = useToast()
  const [edit, setEdit] = useState<Partial<User> | null>(null)
  const [del, setDel] = useState<User | null>(null)
  const isAdmin = user?.role === 'admin'
  const run = async (fn: () => Promise<unknown>, msg: string) => { try { await fn(); await reloadMeta(); toast(msg) } catch (e) { toast((e as Error).message, 'err') } }
  return (
    <Section title="People on this box" actions={isAdmin && <button type="button" className="btn primary sm" onClick={() => setEdit({ role: 'member' })}><Icon name="plus" size={14} />Add person</button>}
      sub="Everyone signs in with their own account and has their own vault, locked with their own master password. Admins manage accounts; nobody — not even an admin — can open someone else’s vault.">
      <div className="set-people">
        {users.map(u => (
          <div key={u.id} className="set-person">
            <Avatar name={u.name} email={u.email} size={34} />
            <div className="grow">
              <div className="set-person-name">{u.name || <span className="muted">—</span>}{u.id === user?.id && <span className="badge">you</span>}{u.role === 'admin' && <span className="badge accent">admin</span>}</div>
              <div className="muted small ellipsis">{u.email}</div>
            </div>
            {isAdmin && <span className="row" style={{ justifyContent: 'flex-end' }}><button type="button" className="btn ghost sm" onClick={() => setEdit(u)}>Edit</button>{u.id !== user?.id && <button type="button" className="btn ghost sm danger-text" onClick={() => setDel(u)}>Remove</button>}</span>}
          </div>
        ))}
      </div>
      {status?.auth_mode !== 'local' && <p className="muted small mt">Auth mode is <code>{status?.auth_mode}</code>: users are created automatically on first visit; passwords are not used here.</p>}
      {edit && <UserModal user={edit} local={status?.auth_mode === 'local'} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reloadMeta() }} />}
      {del && <Confirm confirmLabel="Remove" title={`Remove ${del.name || del.email}?`} message="Their account is deleted together with their vault, for good." onCancel={() => setDel(null)} onConfirm={() => { const d = del; setDel(null); run(() => api.del(`${V1}/users/${d.id}`), 'User removed') }} />}
    </Section>
  )
}

function UserModal({ user, local, onClose, onSaved }: { user: Partial<User>; local: boolean; onClose: () => void; onSaved: () => void }) {
  const { toast } = useToast()
  const [f, setF] = useState({ name: user.name || '', email: user.email || '', password: '', role: user.role || 'member' })
  const [busy, setBusy] = useState(false)
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true)
    try { if (user.id) await api.put(`${V1}/users/${user.id}`, f); else await api.post(`${V1}/users`, f); toast(user.id ? 'User saved' : 'User added'); onSaved() } catch (e) { toast((e as Error).message, 'err') } finally { setBusy(false) }
  }
  return (
    <Modal title={user.id ? 'Edit person' : 'Add a person'} onClose={onClose} size="sm">
      <form onSubmit={save} className="grid" style={{ gap: 14 }}>
        <Field label="Name"><input value={f.name} onChange={e => setF({ ...f, name: e.target.value })} autoFocus required maxLength={60} /></Field>
        <Field label="Email" help="Used to sign in."><input type="email" value={f.email} onChange={e => setF({ ...f, email: e.target.value })} required /></Field>
        {local && <Field label={user.id ? 'New password (leave empty to keep)' : 'Password'} help="At least 8 characters."><input type="password" value={f.password} onChange={e => setF({ ...f, password: e.target.value })} minLength={user.id ? 0 : 8} required={!user.id} autoComplete="new-password" /></Field>}
        <Field group label="Role"><Segmented value={f.role} onChange={v => setF({ ...f, role: v })} options={[{ value: 'member', label: 'Member' }, { value: 'admin', label: 'Admin' }]} /></Field>
        <div className="form-actions"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{user.id ? 'Save' : 'Add person'}</button></div>
      </form>
    </Modal>
  )
}

function Profile() {
  const { user, setUser, status } = useApp()
  const { toast } = useToast()
  const [f, setF] = useState({ name: user?.name || '', email: user?.email || '', current_password: '', new_password: '' })
  const [busy, setBusy] = useState(false)
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true)
    try { setUser(await api.put(`${V1}/auth/me`, f)); setF(x => ({ ...x, current_password: '', new_password: '' })); toast('Profile saved') } catch (e) { toast((e as Error).message, 'err') } finally { setBusy(false) }
  }
  return (
    <form onSubmit={save} className="stack loose">
      <div className="set-profile">
        <Avatar name={user?.name} email={user?.email} size={56} />
        <div className="grow"><h3>{user?.name || user?.email}</h3><p className="muted small">{user?.email} · {user?.role}</p></div>
      </div>
      <Section title="You" sub="Your sign-in to Pocket Vault. Your vault’s email and master password are under Security.">
        <div className="stack">
          <Field label="Name"><input value={f.name} onChange={e => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Email"><input type="email" value={f.email} onChange={e => setF({ ...f, email: e.target.value })} /></Field>
        </div>
      </Section>
      {status?.auth_mode === 'local' && <Section title="Password" sub="Leave empty to keep the current one."><div className="stack">
        <Field label="Current password"><input type="password" value={f.current_password} onChange={e => setF({ ...f, current_password: e.target.value })} autoComplete="current-password" /></Field>
        <Field label="New password" help="At least 8 characters."><input type="password" value={f.new_password} onChange={e => setF({ ...f, new_password: e.target.value })} autoComplete="new-password" /></Field>
      </div></Section>}
      <div className="row"><button className="btn primary" disabled={busy}>Save changes</button></div>
    </form>
  )
}

