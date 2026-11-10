// Health: which passwords to change first. Worked out in this browser; only
// the counts go to your other Pocket apps, and only if you allow it.
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, V1 } from '../lib/api'
import { useApp } from '../lib/app-context'
import { useVault } from '../lib/vault-context'
import { analyse, checkBreaches, summary } from '../lib/health'
import type { Item } from '../lib/vault'
import type { Settings } from '../lib/types'
import { fmtDate } from '../lib/format'
import { ItemIcon } from './Vault'
import { Icon } from '../components/icons'
import { Card, Empty, errMsg, PageHeader, Switch, useToast } from '../components/ui'

type Tab = 'breached' | 'weak' | 'reused' | 'old' | 'http' | 'empty'

export default function Health() {
  const { items } = useVault()
  const { settings, setSettings } = useApp()
  const { toast } = useToast()
  const navigate = useNavigate()
  const [breached, setBreached] = useState<Map<string, number>>(new Map())
  const [checked, setChecked] = useState(false)
  const [progress, setProgress] = useState<[number, number] | null>(null)
  const h = useMemo(() => analyse(items, breached, checked), [items, breached, checked])
  const [tab, setTab] = useState<Tab>('weak')

  // share the numbers (never the items) when the person allowed it
  useEffect(() => {
    if (!settings?.share_health || !h.logins.length) return
    const t = setTimeout(() => api.put(`${V1}/vault/health`, summary(h)).catch(() => {}), 1500)
    return () => clearTimeout(t)
  }, [settings?.share_health, h])

  const runBreach = async () => {
    setProgress([0, 1])
    try { const m = await checkBreaches(items, (d, t) => setProgress([d, t])); setBreached(m); setChecked(true); setTab('breached'); toast(m.size ? `${m.size} passwords were found in leaks` : 'None of your passwords were found in leaks') }
    catch (e) { toast(errMsg(e), 'err') } finally { setProgress(null) }
  }
  const allowBreach = async (v: boolean) => { try { setSettings(await api.put<Settings>(`${V1}/settings`, { breach_check: v })) } catch (e) { toast(errMsg(e), 'err') } }

  const lists: Record<Tab, { label: string; items: Item[]; help: string; icon: string }> = {
    breached: { label: 'In leaks', items: h.logins.filter(i => breached.has(i.id)), help: 'Seen in data breaches: anyone can try these. Change them first.', icon: 'shield-alert' },
    weak: { label: 'Weak', items: h.weak, help: 'Short, common or easy to guess.', icon: 'alert' },
    reused: { label: 'Reused', items: h.reusedItems, help: 'One leak opens every site that shares the password.', icon: 'copy' },
    old: { label: 'Over a year old', items: h.old, help: 'Not changed for more than a year. Worth a look for important accounts.', icon: 'clock' },
    http: { label: 'Not encrypted', items: h.http, help: 'Saved for an http:// address: the password crosses the network in the open.', icon: 'globe' },
    empty: { label: 'No password', items: h.noPassword, help: 'Logins without a password or passkey.', icon: 'key' },
  }
  const reuseCount = (it: Item) => h.reused.find(r => r.items.some(x => x.id === it.id))?.items.length || 0
  const cur = lists[tab]
  return (
    <div className="page">
      <PageHeader title="Health" sub="Which passwords to change first. Checked here, in your browser." />
      <div className="health-top">
        <div className={`health-score s${h.score >= 90 ? 4 : h.score >= 75 ? 3 : h.score >= 50 ? 2 : 1}`}>
          <b className="tnum">{h.score}</b><span>out of 100</span>
        </div>
        <div className="health-tiles">
          {(Object.keys(lists) as Tab[]).filter(k => k !== 'breached' || checked).map(k => (
            <button key={k} type="button" className={`health-tile ${tab === k ? 'active' : ''} ${lists[k].items.length ? 'has' : ''}`} onClick={() => setTab(k)}>
              <Icon name={lists[k].icon} size={16} /><span className="tnum">{lists[k].items.length}</span><small>{lists[k].label}</small>
            </button>
          ))}
        </div>
      </div>
      <Card title="Leaked passwords" sub={<>Have I Been Pwned knows billions of leaked passwords. Only the first 5 characters of each password’s SHA-1 hash are sent — never a password — and the answer is checked here.</>}
        actions={settings?.breach_check ? <button type="button" className="btn sm" onClick={runBreach} disabled={!!progress}>{progress ? <><span className="spinner" />{progress[0]}/{progress[1]}</> : checked ? 'Check again' : 'Check now'}</button> : undefined}>
        <label className="check-row small"><Switch checked={!!settings?.breach_check} onChange={allowBreach} size="sm" label="Allow" />Allow checks with Have I Been Pwned (api.pwnedpasswords.com)</label>
      </Card>
      <Card title={cur.label} sub={cur.help} flush>
        {cur.items.length === 0 ? <div className="pad"><Empty title="Nothing here" icon="check-circle">{tab === 'breached' ? 'None of your passwords turned up in a leak.' : 'Well done.'}</Empty></div> : (
          <ul className="health-list">
            {cur.items.map(it => (
              <li key={it.id}><button type="button" className="health-row" onClick={() => navigate(`/item/${it.id}`)}>
                <ItemIcon it={it} size={30} />
                <span className="grow"><span className="ellipsis vr-name">{it.name}</span><span className="vr-sub ellipsis">{it.login?.username}</span></span>
                {tab === 'breached' && <span className="badge s0">{(breached.get(it.id) || 0).toLocaleString()}×</span>}
                {tab === 'reused' && <span className="badge s1">{reuseCount(it)} sites</span>}
                {tab === 'old' && <span className="muted small">{fmtDate((it.login?.passwordRevisionDate || it.creationDate).slice(0, 10))}</span>}
                <Icon name="chevron-right" size={15} className="muted" />
              </button></li>
            ))}
          </ul>
        )}
      </Card>
      <p className="muted small">{h.logins.length} logins · {h.withTotp} with authenticator codes. {settings?.share_health ? 'These numbers (only the numbers) are shared with your other Pocket apps.' : 'Nothing here is shared; switch it on in Settings → Connected apps.'}</p>
    </div>
  )
}
