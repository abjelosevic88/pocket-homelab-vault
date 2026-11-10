// Add or edit an item. Everything typed here is encrypted in this browser
// before it is saved.
import React, { useState } from 'react'
import { useApp } from '../lib/app-context'
import { useVault } from '../lib/vault-context'
import { cardBrand, IDENTITY_FIELDS, TYPE_CARD, TYPE_IDENTITY, TYPE_LOGIN, TYPE_NAME, TYPE_NOTE, TYPE_SSH, type CustomField, type Identity, type Item } from '../lib/vault'
import { DEFAULT_GEN, generate, strength, type GenOptions } from '../lib/generator'
import { parseTotp } from '../lib/crypto'
import { Icon } from './icons'
import { Select } from './Select'
import { errMsg, Field, Modal, Segmented, Switch, useToast } from './ui'

const ID_LABEL: Record<(typeof IDENTITY_FIELDS)[number], string> = { title: 'Title', firstName: 'First name', middleName: 'Middle name', lastName: 'Last name', company: 'Company', email: 'Email', phone: 'Phone', username: 'Username',
  address1: 'Address', address2: 'Address line 2', address3: 'Address line 3', city: 'City', state: 'State or region', postalCode: 'Postcode', country: 'Country', ssn: 'National ID / SSN', passportNumber: 'Passport number', licenseNumber: 'Driving licence number' }

export function ItemForm({ item, onClose, onSaved }: { item: Item; onClose: () => void; onSaved: (it: Item) => void }) {
  const { folders, saveItem } = useVault()
  const { settings } = useApp()
  const { toast } = useToast()
  const [it, setIt] = useState<Item>(() => structuredClone(item))
  const [busy, setBusy] = useState(false)
  const [showPw, setShowPw] = useState(!item.id)
  const isNew = !item.id
  const set = (patch: Partial<Item>) => setIt(x => ({ ...x, ...patch }))
  const setLogin = (patch: Partial<NonNullable<Item['login']>>) => setIt(x => ({ ...x, login: { ...x.login!, ...patch } }))
  const setCard = (patch: Partial<NonNullable<Item['card']>>) => setIt(x => ({ ...x, card: { ...x.card!, ...patch } }))
  const setId = (k: keyof Identity, v: string) => setIt(x => ({ ...x, identity: { ...x.identity!, [k]: v } }))
  const gen = async () => { const pw = await generate({ ...DEFAULT_GEN, ...(settings?.generator || {}) } as GenOptions); setLogin({ password: pw }); setShowPw(true) }
  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!it.name.trim()) { toast('Give it a name', 'err'); return }
    if (it.login?.totp && !parseTotp(it.login.totp)) { toast('The authenticator key doesn’t look right', 'err'); return }
    setBusy(true)
    try { const saved = await saveItem({ ...it, name: it.name.trim() }); toast(isNew ? 'Saved to your vault' : 'Saved'); onSaved(saved) } catch (err) { toast(errMsg(err), 'err') } finally { setBusy(false) }
  }
  const st = it.login?.password ? strength(it.login.password) : null
  return (
    <Modal title={`${isNew ? 'New' : 'Edit'} ${(TYPE_NAME[it.type] || 'item').toLowerCase()}`} onClose={onClose} size="lg">
      <form onSubmit={save} className="item-form stack">
        <div className="two-col tight">
          <Field label="Name"><input value={it.name} onChange={e => set({ name: e.target.value })} autoFocus={isNew} required maxLength={500} placeholder={it.type === TYPE_LOGIN ? 'GitHub' : it.type === TYPE_CARD ? 'Visa' : ''} /></Field>
          <Field label="Folder"><Select value={it.folderId || ''} onChange={v => set({ folderId: v || null })} options={[{ value: '', label: 'No folder' }, ...folders.map(f => ({ value: f.id, label: f.name }))]} /></Field>
        </div>

        {it.type === TYPE_LOGIN && it.login && <>
          <Field label="Username or email"><input value={it.login.username} onChange={e => setLogin({ username: e.target.value })} autoComplete="off" spellCheck={false} /></Field>
          <Field label="Password">
            <div className="input-group">
              <input type={showPw ? 'text' : 'password'} value={it.login.password} onChange={e => setLogin({ password: e.target.value })} autoComplete="new-password" spellCheck={false} className="mono" />
              <button type="button" className="btn" onClick={() => setShowPw(s => !s)} aria-label={showPw ? 'Hide' : 'Show'} title={showPw ? 'Hide' : 'Show'}><Icon name={showPw ? 'eye-off' : 'eye'} size={16} /></button>
              <button type="button" className="btn" onClick={gen} aria-label="Generate a password" title="Generate a password (with the generator’s settings)"><Icon name="dice" size={16} /></button>
            </div>
          </Field>
          {st && <div className={`meter s${st.score}`}><span style={{ width: `${(st.score + 1) * 20}%` }} /><b>{st.label}</b></div>}
          <Field label="Authenticator key (TOTP)" help="The secret or otpauth:// link a site shows when you turn on two-step login. The code then appears here and in the apps.">
            <input value={it.login.totp} onChange={e => setLogin({ totp: e.target.value })} autoComplete="off" spellCheck={false} className="mono" placeholder="JBSW Y3DP EHPK 3PXP" />
          </Field>
          <div className="stack tight">
            <span className="field-label">Websites</span>
            {it.login.uris.map((u, i) => (
              <div key={i} className="row">
                <input value={u.uri} onChange={e => setLogin({ uris: it.login!.uris.map((x, j) => j === i ? { ...x, uri: e.target.value } : x) })} placeholder="https://example.com" autoComplete="off" spellCheck={false} />
                <Select className="uri-match" value={String(u.match ?? '')} onChange={v => setLogin({ uris: it.login!.uris.map((x, j) => j === i ? { ...x, match: v === '' ? null : Number(v) } : x) })} ariaLabel="How to match"
                  options={[{ value: '', label: 'Default match' }, { value: '0', label: 'Same domain' }, { value: '1', label: 'Same host' }, { value: '2', label: 'Starts with' }, { value: '3', label: 'Exactly' }, { value: '4', label: 'Pattern' }, { value: '5', label: 'Never' }]} />
                <button type="button" className="btn ghost icon-only" aria-label="Remove" onClick={() => setLogin({ uris: it.login!.uris.filter((_, j) => j !== i) })}><Icon name="x" size={15} /></button>
              </div>
            ))}
            <div><button type="button" className="btn sm ghost" onClick={() => setLogin({ uris: [...it.login!.uris, { uri: '', match: null }] })}><Icon name="plus" size={14} />Add a website</button></div>
          </div>
          {it.login.passkeys > 0 && <p className="muted small"><Icon name="key" size={13} /> A passkey is saved with this login; it stays as it is.</p>}
        </>}

        {it.type === TYPE_CARD && it.card && <>
          <Field label="Cardholder"><input value={it.card.cardholderName} onChange={e => setCard({ cardholderName: e.target.value })} autoComplete="off" /></Field>
          <div className="two-col tight">
            <Field label="Number"><input value={it.card.number} onChange={e => { const n = e.target.value.replace(/[^\d ]/g, ''); setCard({ number: n.replace(/\s/g, ''), brand: it.card!.brand || cardBrand(n) }) }} inputMode="numeric" autoComplete="off" className="mono" /></Field>
            <Field label="Brand"><Select value={it.card.brand} onChange={v => setCard({ brand: v })} options={['', 'Visa', 'Mastercard', 'Amex', 'Discover', 'Diners Club', 'JCB', 'Maestro', 'UnionPay', 'RuPay', 'Other'].map(b => ({ value: b, label: b || '—' }))} /></Field>
          </div>
          <div className="three-col tight">
            <Field label="Expiry month"><Select value={it.card.expMonth} onChange={v => setCard({ expMonth: v })} options={[{ value: '', label: '—' }, ...Array.from({ length: 12 }, (_, i) => ({ value: String(i + 1), label: String(i + 1).padStart(2, '0') }))]} /></Field>
            <Field label="Expiry year"><input value={it.card.expYear} onChange={e => setCard({ expYear: e.target.value.replace(/\D/g, '').slice(0, 4) })} inputMode="numeric" placeholder="2028" /></Field>
            <Field label="Security code"><input type={showPw ? 'text' : 'password'} value={it.card.code} onChange={e => setCard({ code: e.target.value.replace(/\D/g, '').slice(0, 4) })} inputMode="numeric" autoComplete="off" className="mono" /></Field>
          </div>
        </>}

        {it.type === TYPE_IDENTITY && it.identity && <div className="id-grid">
          {IDENTITY_FIELDS.map(k => <Field key={k} label={ID_LABEL[k]}><input value={it.identity![k]} onChange={e => setId(k, e.target.value)} autoComplete="off" /></Field>)}
        </div>}

        {it.type === TYPE_SSH && it.sshKey && <>
          <Field label="Private key"><textarea value={it.sshKey.privateKey} onChange={e => set({ sshKey: { ...it.sshKey!, privateKey: e.target.value } })} rows={5} className="mono" spellCheck={false} /></Field>
          <Field label="Public key"><textarea value={it.sshKey.publicKey} onChange={e => set({ sshKey: { ...it.sshKey!, publicKey: e.target.value } })} rows={2} className="mono" spellCheck={false} /></Field>
          <Field label="Fingerprint"><input value={it.sshKey.keyFingerprint} onChange={e => set({ sshKey: { ...it.sshKey!, keyFingerprint: e.target.value } })} className="mono" /></Field>
        </>}

        <Field label={it.type === TYPE_NOTE ? 'Note' : 'Notes'}><textarea value={it.notes} onChange={e => set({ notes: e.target.value })} rows={it.type === TYPE_NOTE ? 10 : 3} /></Field>

        <Fields fields={it.fields} onChange={fields => set({ fields })} />

        <div className="row wrap">
          <label className="check-row small"><Switch checked={it.favorite} onChange={v => set({ favorite: v })} size="sm" label="Favourite" />Favourite</label>
          <label className="check-row small" title="The apps ask for your master password before showing it"><Switch checked={it.reprompt === 1} onChange={v => set({ reprompt: v ? 1 : 0 })} size="sm" label="Ask for the master password" />Ask for the master password to open it</label>
        </div>
        <div className="form-actions"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></div>
      </form>
    </Modal>
  )
}

function Fields({ fields, onChange }: { fields: CustomField[]; onChange: (f: CustomField[]) => void }) {
  const upd = (i: number, p: Partial<CustomField>) => onChange(fields.map((f, j) => (j === i ? { ...f, ...p } : f)))
  return (
    <div className="stack tight">
      {fields.length > 0 && <span className="field-label">Custom fields</span>}
      {fields.map((f, i) => (
        <div key={i} className="row custom-field">
          <input value={f.name} onChange={e => upd(i, { name: e.target.value })} placeholder="Name" aria-label="Field name" />
          {f.type === 2 ? <Segmented size="sm" value={f.value === 'true' ? 'true' : 'false'} onChange={v => upd(i, { value: v })} options={[{ value: 'true', label: 'Yes' }, { value: 'false', label: 'No' }]} />
            : <input type={f.type === 1 ? 'password' : 'text'} value={f.value} onChange={e => upd(i, { value: e.target.value })} placeholder="Value" aria-label="Field value" autoComplete="off" />}
          <button type="button" className="btn ghost icon-only" aria-label="Remove" onClick={() => onChange(fields.filter((_, j) => j !== i))}><Icon name="x" size={15} /></button>
        </div>
      ))}
      <div className="row wrap">
        <button type="button" className="btn sm ghost" onClick={() => onChange([...fields, { name: '', value: '', type: 0, linkedId: null }])}><Icon name="plus" size={14} />Text field</button>
        <button type="button" className="btn sm ghost" onClick={() => onChange([...fields, { name: '', value: '', type: 1, linkedId: null }])}><Icon name="eye-off" size={14} />Hidden field</button>
        <button type="button" className="btn sm ghost" onClick={() => onChange([...fields, { name: '', value: 'false', type: 2, linkedId: null }])}><Icon name="check-square" size={14} />Yes / no</button>
      </div>
    </div>
  )
}

