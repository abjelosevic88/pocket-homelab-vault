// Apps & activity: every app signed in to the vault (sign one out, or all
// of them), and what happened: sign-ins, wrong tries, security changes.
import { useState } from 'react'
import { api, V1 } from '../lib/api'
import { useVault } from '../lib/vault-context'
import type { VaultDevice, VaultEvent } from '../lib/types'
import { ago, fmtDateTime } from '../lib/format'
import { Icon } from '../components/icons'
import { Card, Confirm, Empty, errMsg, Loading, PageHeader, useAsync, useToast } from '../components/ui'

const KIND_ICON: Record<VaultDevice['kind'], string> = { phone: 'smartphone', extension: 'puzzle', desktop: 'monitor', web: 'globe', cli: 'terminal' }

export const EVENT: Record<string, [string, string, string]> = {
  signed_in: ['Signed in', 'log-out', ''],
  new_device: ['Signed in on a new device', 'smartphone', 'accent'],
  signin_failed: ['Wrong master password', 'alert', 'warn'],
  twofactor_failed: ['Wrong two-step code', 'alert', 'warn'],
  twofactor_on: ['Two-step login turned on', 'shield-check', 'ok'],
  twofactor_off: ['Two-step login turned off', 'shield-alert', 'warn'],
  password_changed: ['Master password changed', 'key', 'accent'],
  kdf_changed: ['Key settings changed', 'key', 'accent'],
  device_removed: ['An app was signed out', 'log-out', ''],
  signed_out_everywhere: ['Every app was signed out', 'log-out', 'accent'],
  imported: ['Items imported', 'upload', ''],
  created: ['Vault created', 'shield-check', 'ok'],
  purged: ['Every item deleted', 'trash', 'warn'],
}

function appName(d: { name: string; type_name: string }) {
  const n = d.name.toLowerCase()
  if (d.name === 'Pocket Vault web') return 'This web vault'
  if (/^iphone|^ipad/i.test(d.name)) return `Bitwarden on ${d.name.replace(/\d+,\d+$/, '').trim() || 'iPhone'}`
  if (['chrome', 'firefox', 'edge', 'safari', 'opera', 'vivaldi', 'brave'].includes(n)) return `${d.type_name}`
  if (n === 'macos' || n === 'windows' || n === 'linux') return d.type_name
  return `${d.type_name} · ${d.name}`
}

export default function Activity() {
  const { toast } = useToast()
  const { session, reloadStatus } = useVault()
  const devs = useAsync(() => api.get<VaultDevice[]>(`${V1}/vault/devices`), [])
  const evs = useAsync(() => api.get<VaultEvent[]>(`${V1}/vault/activity?limit=200`), [])
  const [remove, setRemove] = useState<VaultDevice | null>(null)
  const [all, setAll] = useState(false)
  const thisDevice = localStorage.getItem('pvt-device')
  return (
    <div className="page">
      <PageHeader title="Apps & activity" sub="Everything signed in to your vault, and what happened lately." />
      <Card title="Signed-in apps" flush actions={<button type="button" className="btn sm ghost danger-text" onClick={() => setAll(true)}>Sign out everywhere</button>}
        sub="Signing an app out stops it at once; it needs your master password to come back.">
        {!devs.data ? <div className="pad"><Loading /></div> : devs.data.length === 0 ? <div className="pad"><Empty title="No apps yet" icon="smartphone">Sign in with the Bitwarden apps (see Bitwarden apps).</Empty></div> : (
          <ul className="dev-list">
            {devs.data.map(d => (
              <li key={d.id} className="dev-row">
                <span className="dev-ico"><Icon name={KIND_ICON[d.kind]} size={18} /></span>
                <span className="grow"><b>{appName(d)}</b>{d.id === thisDevice && <span className="badge accent">this browser</span>}
                  <span className="muted small block-line">Last used {ago(d.last_used)}{d.ip ? ` · ${d.ip}` : ''} · first {fmtDateTime(d.created_at, true)}{d.push ? ' · push' : ''}</span></span>
                {d.id !== thisDevice && <button type="button" className="btn sm ghost" onClick={() => setRemove(d)}>Sign out</button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Activity" flush sub="Sign-ins, wrong tries and changes to security, newest first. Never what’s in your vault.">
        {!evs.data ? <div className="pad"><Loading /></div> : evs.data.length === 0 ? <div className="pad"><Empty title="Nothing yet" icon="clock" /></div> : (
          <ul className="ev-list">
            {evs.data.map(e => { const [label, icon, tone] = EVENT[e.kind] || [e.kind, 'dot', '']; return (
              <li key={e.id} className={`ev-row ${tone}`}><Icon name={icon} size={15} /><span className="grow">{label}{e.device_name && <span className="muted"> · {e.device_name}</span>}{e.detail && <span className="muted"> · {e.detail}</span>}</span><span className="muted small nowrap" title={fmtDateTime(e.at)}>{ago(e.at)}{e.ip ? ` · ${e.ip}` : ''}</span></li>
            ) })}
          </ul>
        )}
      </Card>
      {remove && <Confirm title={`Sign out ${appName(remove)}?`} confirmLabel="Sign out" message="It stops syncing now and asks for the master password next time." onCancel={() => setRemove(null)}
        onConfirm={async () => { const d = remove; setRemove(null); try { await api.del(`${V1}/vault/devices/${d.id}`); devs.reload(); evs.reload(); toast('Signed out') } catch (e) { toast(errMsg(e), 'err') } }} />}
      {all && <Confirm title="Sign out every app?" confirmLabel="Sign out everywhere" message="Every app — including this page — needs your master password again. Use this if a device was lost." onCancel={() => setAll(false)}
        onConfirm={async () => { setAll(false); try { await api.post(`${V1}/vault/sign-out-everywhere`); toast('Every app was signed out'); await reloadStatus(); session?.onExpired() } catch (e) { toast(errMsg(e), 'err') } }} />}
    </div>
  )
}
