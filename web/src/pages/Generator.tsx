// The password generator: random passwords or passphrases, made in this
// browser. The last setup is remembered (in your settings, not the vault).
import { useCallback, useEffect, useRef, useState } from 'react'
import { api, V1 } from '../lib/api'
import { useApp } from '../lib/app-context'
import { DEFAULT_GEN, genBits, generate, type GenOptions } from '../lib/generator'
import type { Settings } from '../lib/types'
import { useCopy } from '../components/Copy'
import { Icon } from '../components/icons'
import { Card, PageHeader, Segmented, SettingRow, Switch } from '../components/ui'

export default function Generator() {
  const { settings, setSettings } = useApp()
  const copy = useCopy()
  const [o, setO] = useState<GenOptions>(() => ({ ...DEFAULT_GEN, ...(settings?.generator || {}) } as GenOptions))
  const [pw, setPw] = useState('')
  const [history, setHistory] = useState<string[]>([])
  const saveTimer = useRef<number | undefined>(undefined)
  const make = useCallback(async (opts: GenOptions) => { const p = await generate(opts); setPw(p); setHistory(h => [p, ...h.filter(x => x !== p)].slice(0, 8)) }, [])
  useEffect(() => { make(o) }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const change = (patch: Partial<GenOptions>) => {
    const n = { ...o, ...patch }
    setO(n); make(n)
    clearTimeout(saveTimer.current)
    saveTimer.current = window.setTimeout(() => { api.put<Settings>(`${V1}/settings`, { generator: n }).then(setSettings).catch(() => {}) }, 800)
  }
  const bits = genBits(o)
  const rating = bits < 50 ? ['Weak', 's1'] : bits < 70 ? ['Good', 's2'] : bits < 100 ? ['Strong', 's3'] : ['Very strong', 's4']
  return (
    <div className="page narrow">
      <PageHeader title="Generator" sub="Strong, random and new every time. Nothing here is saved unless you copy it into an item." />
      <Card>
        <div className="gen-out">
          <output className="gen-pw mono" aria-live="polite">{colour(pw)}</output>
          <div className="row">
            <button type="button" className="btn ghost icon-only" aria-label="Another one" title="Another one" onClick={() => make(o)}><Icon name="refresh" size={18} /></button>
            <button type="button" className="btn primary" onClick={() => copy(pw, 'Password', true)}><Icon name="copy" size={15} />Copy</button>
          </div>
        </div>
        <div className="gen-meta small"><span className={`badge ${rating[1]}`}>{rating[0]}</span><span className="muted">about {bits} bits — {crackTime(bits)} to guess at a trillion tries a second</span></div>
      </Card>
      <Card title="Options">
        <SettingRow title="Kind"><Segmented value={o.kind} onChange={v => change({ kind: v })} options={[{ value: 'password', label: 'Password' }, { value: 'passphrase', label: 'Passphrase' }]} /></SettingRow>
        {o.kind === 'password' ? <>
          <SettingRow title="Length" help={`${o.length} characters`}>
            <input type="range" min={8} max={64} value={o.length} onChange={e => change({ length: Number(e.target.value) })} aria-label="Length" className="gen-range" />
          </SettingRow>
          <SettingRow title="A–Z"><Switch checked={o.upper} onChange={v => change({ upper: v })} label="Upper case" /></SettingRow>
          <SettingRow title="a–z"><Switch checked={o.lower} onChange={v => change({ lower: v })} label="Lower case" /></SettingRow>
          <SettingRow title="0–9"><Switch checked={o.digits} onChange={v => change({ digits: v })} label="Digits" /></SettingRow>
          <SettingRow title="!@#$%^&*"><Switch checked={o.symbols} onChange={v => change({ symbols: v })} label="Symbols" /></SettingRow>
          <SettingRow title="No look-alikes" help="Leaves out l, I, 1, O, 0 and o — easier to type from a screen."><Switch checked={o.avoid} onChange={v => change({ avoid: v })} label="No look-alikes" /></SettingRow>
        </> : <>
          <SettingRow title="Words" help={`${o.words} words from a list of 7,776`}>
            <input type="range" min={3} max={12} value={o.words} onChange={e => change({ words: Number(e.target.value) })} aria-label="Words" className="gen-range" />
          </SettingRow>
          <SettingRow title="Between words"><Segmented size="sm" value={o.separator} onChange={v => change({ separator: v })} options={['-', '.', '_', ' ', ','].map(s => ({ value: s, label: s === ' ' ? 'space' : s }))} /></SettingRow>
          <SettingRow title="Capitals"><Switch checked={o.capital} onChange={v => change({ capital: v })} label="Capitals" /></SettingRow>
          <SettingRow title="A number" help="One digit after one of the words."><Switch checked={o.number} onChange={v => change({ number: v })} label="A number" /></SettingRow>
        </>}
      </Card>
      {history.length > 1 && <Card title="Made just now" sub="Kept only while this page is open.">
        <ul className="gen-hist">{history.slice(1).map(h => <li key={h}><span className="mono ellipsis">{h}</span><button type="button" className="btn ghost icon-only sm" aria-label="Copy" onClick={() => copy(h, 'Password', true)}><Icon name="copy" size={14} /></button></li>)}</ul>
      </Card>}
    </div>
  )
}

/** Digits and symbols in their own colour, as the Bitwarden apps show them. */
function colour(pw: string) {
  return Array.from(pw).map((c, i) => <span key={i} className={/\d/.test(c) ? 'pw-d' : /[^a-zA-Z0-9]/.test(c) ? 'pw-s' : undefined}>{c}</span>)
}

function crackTime(bits: number): string {
  const secs = 2 ** bits / 1e12 / 2
  const units: [number, string][] = [[31557600 * 1e9, 'billion years'], [31557600 * 1e6, 'million years'], [31557600 * 1e3, 'thousand years'], [31557600, 'years'], [86400, 'days'], [3600, 'hours'], [60, 'minutes'], [1, 'seconds']]
  for (const [s, name] of units) if (secs >= s) { const n = secs / s; return `${n >= 1000 ? 'over a thousand' : Math.round(n).toLocaleString()} ${name}` }
  return 'under a second'
}
