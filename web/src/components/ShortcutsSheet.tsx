import { Modal } from './ui'

const GROUPS: { title: string; keys: [string[], string][] }[] = [
  { title: 'Go to', keys: [[['v'], 'All items'], [['f'], 'Favourites'], [['g'], 'Generator'], [['h'], 'Health'], [['a'], 'Apps & activity'], [[','], 'Settings'], [['/'], 'Find an item'], [['⌘', 'K'], 'Find an item']] },
  { title: 'Vault', keys: [[['n'], 'New login'], [['l'], 'Lock'], [['⇧', '↵'], 'In search: copy the password']] },
  { title: 'An open item', keys: [[['u'], 'Copy the username'], [['p'], 'Copy the password'], [['t'], 'Copy the code'], [['e'], 'Edit']] },
  { title: 'Window', keys: [[['['], 'Show or hide the sidebar'], [['esc'], 'Close a dialog or menu']] },
  { title: 'Help', keys: [[['?'], 'This sheet']] },
]

export function ShortcutsSheet({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="Keyboard shortcuts" onClose={onClose} size="lg">
      <div className="shortcuts">
        {GROUPS.map(g => (
          <section key={g.title}>
            <h4 className="sc-h">{g.title}</h4>
            {g.keys.map(([keys, label]) => (
              <div key={label + keys.join('')} className="sc-row"><span>{label}</span><span className="sc-keys">{keys.map(k => <kbd key={k}>{k}</kbd>)}</span></div>
            ))}
          </section>
        ))}
      </div>
    </Modal>
  )
}
