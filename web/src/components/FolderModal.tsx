import React, { useState } from 'react'
import { useVault } from '../lib/vault-context'
import type { Folder } from '../lib/vault'
import { errMsg, Field, Modal, useToast } from './ui'

export function FolderModal({ folder, onClose, onSaved }: { folder?: Folder; onClose: () => void; onSaved: (f: Folder) => void }) {
  const { saveFolder } = useVault()
  const { toast } = useToast()
  const [name, setName] = useState(folder?.name || '')
  const [busy, setBusy] = useState(false)
  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setBusy(true)
    try { const f = await saveFolder(name.trim(), folder?.id); toast(folder ? 'Folder renamed' : 'Folder added'); onSaved(f) } catch (err) { toast(errMsg(err), 'err') } finally { setBusy(false) }
  }
  return (
    <Modal title={folder ? 'Rename folder' : 'New folder'} onClose={onClose} size="sm">
      <form onSubmit={save} className="stack">
        <Field label="Name" help="Encrypted like everything else in your vault."><input value={name} onChange={e => setName(e.target.value)} autoFocus maxLength={100} required /></Field>
        <div className="form-actions"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !name.trim()}>{folder ? 'Rename' : 'Add folder'}</button></div>
      </form>
    </Modal>
  )
}
