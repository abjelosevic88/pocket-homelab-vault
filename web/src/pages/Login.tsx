import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { api, V1 } from '../lib/api'
import { useApp } from '../lib/app-context'
import { Field } from '../components/ui'
import { Icon } from '../components/icons'
import { passkeysAvailable } from '../lib/passkey'
import { PasskeyCantUnlock, Session } from '../lib/vault'
import { handOverSession } from '../lib/vault-context'

export default function Login({ mode }: { mode: 'login' | 'setup' }) {
  const { status, user, refresh } = useApp()
  const navigate = useNavigate()
  const loc = useLocation()
  const [form, setForm] = useState({ email: '', password: '', name: '' })
  const [err, setErr] = useState(() => new URLSearchParams(window.location.search).get('error') || '')
  const [busy, setBusy] = useState(false)

  if (status && user) return <Navigate to={(loc.state as { from?: string })?.from || '/'} replace />
  if (status && mode === 'setup' && !status.needs_setup) return <Navigate to="/login" replace />
  if (status && mode === 'login' && status.needs_setup) return <Navigate to="/setup" replace />

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true); setErr('')
    try { await api.post(`${V1}/auth/${mode}`, form); await refresh(); navigate(from, { replace: true }) } catch (e: unknown) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const from = (loc.state as { from?: string })?.from || '/'
  const sso = mode === 'login' && status?.oidc
  const passkey = mode === 'login' && !!status?.passkeys && passkeysAvailable()
  const withPasskey = async () => {
    setBusy(true); setErr('')
    try { handOverSession(await Session.withPasskey(undefined, true)) }
    catch (e) { if (!(e instanceof PasskeyCantUnlock)) { setErr((e as Error).message); setBusy(false); return } }
    try { await refresh(); navigate(from, { replace: true }) } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm(f => ({ ...f, [k]: e.target.value }))

  const title = status?.title || 'Pocket Vault'
  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-brand">
          <img src="/favicon.svg" alt="" width={44} height={44} />
          <h1>{title}</h1>
          <p className="login-tagline">{mode === 'setup' ? 'Welcome! Create the first account to get started.' : 'Your passwords, on your own server.'}</p>
        </div>
        {passkey && <>
          <button type="button" className="btn primary lg block" onClick={withPasskey} disabled={busy}>
            <Icon name="fingerprint" size={17} />{busy ? 'Waiting for your passkey…' : 'Sign in with a passkey'}
          </button>
          {!sso && <div className="login-or"><span>or with a password</span></div>}
        </>}
        {sso && <>
          <a className={`btn ${passkey ? '' : 'primary'} lg block`} href={`${V1}/auth/oidc/start?next=${encodeURIComponent(from)}`}>
            <Icon name="key" size={16} />Sign in with {status?.oidc_name || 'Pocket Core'}
          </a>
          <div className="login-or"><span>or with a password</span></div>
        </>}
        <form onSubmit={submit} className="stack">
          {mode === 'setup' && <Field label="Your name"><input value={form.name} onChange={set('name')} autoFocus autoComplete="name" /></Field>}
          <Field label="Email"><input type="email" value={form.email} onChange={set('email')} required autoFocus={mode === 'login' && !sso} autoComplete="username" /></Field>
          <Field label="Password" help={mode === 'setup' ? 'At least 8 characters' : undefined}>
            <input type="password" value={form.password} onChange={set('password')} required minLength={mode === 'setup' ? 8 : 1} autoComplete={mode === 'setup' ? 'new-password' : 'current-password'} />
          </Field>
          {err && <div className="callout danger"><Icon name="alert" size={15} /><span>{err}</span></div>}
          <button className={`btn lg block ${sso || passkey ? '' : 'primary'}`} disabled={busy}>{busy ? 'Please wait…' : mode === 'setup' ? 'Create account' : 'Sign in'}</button>
        </form>
        {mode === 'setup' && <p className="login-note">You become the admin. Add the household under Settings → People; everyone gets their own vault with their own master password, which nobody else can open.</p>}
      </div>
      {status?.version && <p className="login-version">Pocket Vault v{status.version.replace(/^v/, '')}</p>}
    </div>
  )
}
