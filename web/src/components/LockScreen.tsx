// What shows while the vault is locked: unlock with the master password (and
// the authenticator code), or — with no vault yet — create one or bring it
// over from Vaultwarden.
import React, { useState } from 'react'
import { api, ApiError, V1 } from '../lib/api'
import { useApp } from '../lib/app-context'
import { useVault } from '../lib/vault-context'
import { newVaultKeys } from '../lib/crypto'
import { strength } from '../lib/generator'
import { PasskeyCantUnlock, TwoFactorNeeded } from '../lib/vault'
import { passkeysAvailable } from '../lib/passkey'
import { Icon } from './icons'
import { Field, Loading, Switch, errMsg, useToast } from './ui'

export function LockScreen() {
  const { state } = useVault()
  if (state === 'loading') return <div className="lock-wrap"><Loading /></div>
  if (state === 'none') return <CreateVault />
  return <Unlock />
}

function Unlock() {
  const { status, unlock, unlockWithPasskey } = useVault()
  const [pw, setPw] = useState('')
  const [show, setShow] = useState(false)
  const [code, setCode] = useState('')
  const [needCode, setNeedCode] = useState(false)
  const [remember, setRemember] = useState(true)
  const [hint, setHint] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [pkBusy, setPkBusy] = useState(false)
  const canPasskey = passkeysAvailable() && (status?.passkeys_unlock || 0) > 0
  const withPasskey = async () => {
    setPkBusy(true); setErr('')
    try { await unlockWithPasskey() }
    catch (e) { setErr(e instanceof PasskeyCantUnlock ? e.message : errMsg(e)) } finally { setPkBusy(false) }
  }
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!pw) return
    setBusy(true); setErr('')
    try { await unlock(pw, needCode ? code : undefined, remember) }
    catch (e) {
      if (e instanceof TwoFactorNeeded) { setNeedCode(true); setErr(needCode ? 'That code didn’t work. Try the next one.' : '') }
      else setErr(errMsg(e).replace('Username or password is incorrect. Try again', 'That master password isn’t right.'))
    } finally { setBusy(false) }
  }
  return (
    <div className="lock-wrap">
      <form className="lock-card" onSubmit={submit}>
        <div className="lock-ico"><Icon name="lock" size={26} /></div>
        <h2>Your vault is locked</h2>
        <p className="muted">{status?.email}</p>
        {canPasskey && <>
          <button type="button" className="btn primary lg block-btn" onClick={withPasskey} disabled={pkBusy || busy} autoFocus>
            {pkBusy ? <><span className="spinner" />Waiting for your passkey…</> : <><Icon name="fingerprint" size={17} />Unlock with a passkey</>}
          </button>
          <div className="login-or"><span>or with your master password</span></div>
        </>}
        <Field label="Master password">
          <div className="input-group">
            <input type={show ? 'text' : 'password'} value={pw} onChange={e => setPw(e.target.value)} autoFocus={!canPasskey} autoComplete="current-password" spellCheck={false} disabled={busy} />
            <button type="button" className="btn" onClick={() => setShow(s => !s)} aria-label={show ? 'Hide' : 'Show'} title={show ? 'Hide' : 'Show'}><Icon name={show ? 'eye-off' : 'eye'} size={16} /></button>
          </div>
        </Field>
        {needCode && <>
          <Field label="Code from your authenticator app" help="Or a recovery code, which turns two-step login off.">
            <input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" autoFocus placeholder="123 456" disabled={busy} />
          </Field>
          <label className="check-row small"><Switch checked={remember} onChange={setRemember} size="sm" label="Remember" />Don’t ask for a code in this browser for 30 days</label>
        </>}
        {err && <div className="callout danger"><Icon name="alert" size={15} /><span>{err}</span></div>}
        <button className={`btn lg block-btn ${canPasskey ? '' : 'primary'}`} disabled={busy || !pw || (needCode && !code)}>{busy ? <><span className="spinner" />Unlocking…</> : <><Icon name="unlock" size={16} />Unlock</>}</button>
        <div className="lock-foot">
          {status?.hint ? (hint ? <span className="muted small">Hint: {status.hint}</span> : <button type="button" className="linkish small" onClick={() => setHint(true)}>Show my hint</button>) : <span />}
          <span className="muted small">Your key is worked out here; the password never leaves this page.</span>
        </div>
      </form>
    </div>
  )
}

function CreateVault() {
  const { user } = useApp()
  const { status, reloadStatus } = useVault()
  const { toast } = useToast()
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const [hint, setHint] = useState('')
  const [busy, setBusy] = useState(false)
  const [mode, setMode] = useState<'new' | 'move'>('new')
  const st = strength(pw)
  const ok = pw.length >= 12 && pw === pw2 && st.score >= 2 && !hint.toLowerCase().includes(pw.toLowerCase())
  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!ok || !status) return
    setBusy(true)
    try {
      const kdf = { type: 0, iterations: 600000 }
      const k = await newVaultKeys(pw, status.email, kdf)
      await api.post(`${V1}/vault/setup`, { master_password_hash: k.hash, key: k.key, public_key: k.publicKey, private_key: k.privateKey, kdf_type: 0, kdf_iterations: 600000, hint })
      toast('Your vault is ready')
      await reloadStatus()
    } catch (err) { toast(errMsg(err), 'err') } finally { setBusy(false) }
  }
  return (
    <div className="lock-wrap">
      <div className="lock-card wide">
        <div className="lock-ico"><Icon name="shield-check" size={26} /></div>
        <h2>Set up your vault</h2>
        <p className="muted">Passwords, cards, notes and identities, encrypted on your own devices. The Bitwarden apps (browser extension, phone, desktop) work with it too.</p>
        {user?.role === 'admin' && <div className="segmented sm lock-mode" role="tablist">
          <button type="button" role="tab" aria-selected={mode === 'new'} className={mode === 'new' ? 'active' : ''} onClick={() => setMode('new')}>Start a new vault</button>
          <button type="button" role="tab" aria-selected={mode === 'move'} className={mode === 'move' ? 'active' : ''} onClick={() => setMode('move')}>Move from Vaultwarden</button>
        </div>}
        {mode === 'new' ? (
          <form onSubmit={create} className="stack">
            <Field label="Email" help="Your login in the Bitwarden apps. It is part of your key, so it stays as it is."><input value={status?.email || ''} disabled /></Field>
            <Field label="Master password" help="At least 12 characters. A few random words work well. If you forget it, nobody can open your vault — not even an admin.">
              <input type="password" value={pw} onChange={e => setPw(e.target.value)} autoComplete="new-password" autoFocus spellCheck={false} />
            </Field>
            {pw && <div className={`meter s${st.score}`}><span style={{ width: `${(st.score + 1) * 20}%` }} /><b>{st.label}</b></div>}
            <Field label="Type it again"><input type="password" value={pw2} onChange={e => setPw2(e.target.value)} autoComplete="new-password" spellCheck={false} /></Field>
            {pw2 && pw !== pw2 && <p className="small bad">The two don’t match yet.</p>}
            <Field label="Hint (optional)" help="Shown on the unlock screen to you. Don’t write the password itself."><input value={hint} onChange={e => setHint(e.target.value)} maxLength={200} /></Field>
            <button className="btn primary lg block-btn" disabled={!ok || busy}>{busy ? <><span className="spinner" />Making your keys…</> : 'Create my vault'}</button>
            <p className="muted small">Coming from Bitwarden, 1Password or a browser? Create the vault, then use Settings → Backup & data → Import.</p>
          </form>
        ) : <MoveFromVaultwarden onDone={reloadStatus} />}
      </div>
    </div>
  )
}

interface VWReport { accounts: { email: string; status: string; reason?: string; items: number; folders: number; devices: number; two_factor: boolean }[]; key_kept: boolean; notes: string[] }

export function MoveFromVaultwarden({ onDone }: { onDone?: () => void }) {
  const { toast } = useToast()
  const [db, setDb] = useState<File | null>(null)
  const [wal, setWal] = useState<File | null>(null)
  const [key, setKey] = useState<File | null>(null)
  const [replace, setReplace] = useState(false)
  const [busy, setBusy] = useState(false)
  const [rep, setRep] = useState<VWReport | null>(null)
  const go = async () => {
    if (!db) return
    setBusy(true)
    try {
      const fd = new FormData()
      fd.append('db', db)
      if (wal) fd.append('wal', wal)
      if (key) fd.append('key', key)
      fd.append('replace', String(replace))
      const res = await fetch(`${V1}/vault/import/vaultwarden`, { method: 'POST', body: fd, credentials: 'same-origin' })
      const j = await res.json().catch(() => ({}))
      if (!res.ok) throw new ApiError(res.status, j.error || res.statusText)
      setRep(j)
      toast('Vaultwarden data moved over')
      onDone?.()
    } catch (e) { toast(errMsg(e), 'err') } finally { setBusy(false) }
  }
  if (rep) return (
    <div className="stack">
      {rep.accounts.map(a => <div key={a.email} className={`callout ${a.status === 'skipped' ? 'warn' : 'ok'}`}><Icon name={a.status === 'skipped' ? 'info' : 'check-circle'} size={15} />
        <div><b>{a.email}</b> — {a.status === 'skipped' ? a.reason : `${a.items} items, ${a.folders} folders, ${a.devices} signed-in apps${a.two_factor ? ', two-step login on' : ''}`}</div></div>)}
      {rep.key_kept && <p className="small">Vaultwarden’s signing key came along: apps that were signed in stay signed in once your address points here.</p>}
      {rep.notes.map(n => <p key={n} className="small muted">{n}</p>)}
    </div>
  )
  return (
    <div className="stack">
      <p className="small">Everything stays encrypted as it was: accounts with their master passwords, items, folders, favourites, the bin, signed-in apps and the authenticator app. Nothing is decrypted. Take the files from Vaultwarden’s data folder (best with Vaultwarden stopped).</p>
      <Field label="db.sqlite3"><input type="file" accept=".sqlite3,.db,application/octet-stream" onChange={e => setDb(e.target.files?.[0] || null)} /></Field>
      <Field label="db.sqlite3-wal (if it’s there)" help="Holds the latest changes while Vaultwarden runs."><input type="file" onChange={e => setWal(e.target.files?.[0] || null)} /></Field>
      <Field label="rsa_key.pem (recommended)" help="Keeps the apps signed in. Without it they ask for the master password once."><input type="file" accept=".pem" onChange={e => setKey(e.target.files?.[0] || null)} /></Field>
      <label className="check-row small"><Switch checked={replace} onChange={setReplace} size="sm" label="Replace" />Replace vaults that already exist here</label>
      <button type="button" className="btn primary" disabled={!db || busy} onClick={go}>{busy ? <><span className="spinner" />Moving…</> : <><Icon name="upload" size={15} />Move it over</>}</button>
      <p className="muted small">On the server itself: <code>pocket-vault import-vaultwarden -dir /path/to/vw-data</code>.</p>
    </div>
  )
}
