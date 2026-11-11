// Does the newest official Bitwarden CLI still work with Pocket Vault? Signs in to a demo vault
// (DEMO_DATA=true, served over HTTPS) and does what the apps do every day: sync, decrypt, an
// authenticator code, create / edit / bin / restore / delete an item and a folder, sign out.
//
//   BASE=https://localhost:18443 EMAIL=demo@example.com BW=/path/to/bw NODE_EXTRA_CA_CERTS=cert.pem node scripts/bw-compat.mjs
//
// Exit 0 = compatible. Anything else prints the step that broke.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const base = process.env.BASE || 'https://localhost:18443'
const email = process.env.EMAIL || 'demo@example.com'
const master = process.env.MASTER || 'correct horse battery staple'
const bwBin = process.env.BW || 'bw'
const appdata = mkdtempSync(join(tmpdir(), 'bw-compat-'))
let session = ''
let step = ''

function bw(args, input) {
  return execFileSync(bwBin, args, {
    input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 120_000,
    env: { ...process.env, BITWARDENCLI_APPDATA_DIR: appdata, BW_SESSION: session, BW_NOINTERACTION: 'true' },
  }).trim()
}
const json = (args, input) => JSON.parse(bw(args, input))
const encode = obj => Buffer.from(JSON.stringify(obj)).toString('base64')
function check(cond, what) { if (!cond) throw new Error(what) }
async function run(name, fn) { step = name; await fn(); console.log('ok  ', name) }

try {
  const version = bw(['--version'])
  console.log(`bw ${version} against ${base}`)
  await run('point the CLI at the server', () => bw(['config', 'server', base]))
  await run('sign in with the master password', () => { session = bw(['login', email, master, '--raw']); check(session.length > 20, 'no session key') })
  await run('sync', () => check(/complete/i.test(bw(['sync'])), 'sync did not complete'))
  let items
  await run('list and decrypt the items', () => { items = json(['list', 'items']); check(items.length >= 30, `only ${items.length} items`); check(items.some(i => i.name === 'GitHub'), 'names not decrypted') })
  await run('an authenticator code', () => check(/^\d{6}$/.test(bw(['get', 'totp', 'GitHub'])), 'no 6-digit code'))
  await run('folders', () => check(json(['list', 'folders']).some(f => f.name === 'Work'), 'folder names not decrypted'))
  let folder, id
  await run('create a folder', () => { folder = json(['create', 'folder', encode({ name: 'Compat check' })]); check(folder.id, 'no folder id') })
  await run('create a login', () => {
    const t = json(['get', 'template', 'item'])
    Object.assign(t, { name: 'Compat check', folderId: folder.id, notes: 'made by bw-compat',
      login: { username: 'compat', password: 'First-pass-1!', totp: 'JBSWY3DPEHPK3PXP', uris: [{ uri: 'https://compat.example', match: null }] } })
    id = json(['create', 'item', encode(t)]).id
    check(id, 'no item id')
  })
  await run('read it back', () => { const it = json(['get', 'item', id]); check(it.login.password === 'First-pass-1!' && it.login.uris[0].uri === 'https://compat.example', 'fields changed') })
  await run('edit it (password history)', () => {
    const it = json(['get', 'item', id]); it.login.password = 'Second-pass-2!'
    const out = json(['edit', 'item', id, encode(it)])
    check(out.login.password === 'Second-pass-2!' && (out.passwordHistory || []).length === 1, 'edit or history wrong')
  })
  await run('move it to the bin and restore it', () => { bw(['delete', 'item', id]); check(json(['list', 'items', '--trash']).some(i => i.id === id), 'not in the bin'); bw(['restore', 'item', id]) })
  await run('delete it for good', () => { bw(['delete', 'item', id, '--permanent']); let gone = false; try { bw(['get', 'item', id]) } catch { gone = true } check(gone, 'still there') })
  await run('delete the folder', () => bw(['delete', 'folder', folder.id]))
  await run('lock and unlock', () => { bw(['lock']); session = bw(['unlock', master, '--raw']); check(json(['list', 'items']).length >= 30, 'unlock lost the items') })
  await run('sign out', () => bw(['logout']))
  console.log('compatible')
} catch (e) {
  console.error(`BROKEN at "${step}": ${(e.stderr || e.message || String(e)).toString().split('\n').slice(0, 6).join(' | ')}`)
  process.exitCode = 1
} finally {
  rmSync(appdata, { recursive: true, force: true })
}
