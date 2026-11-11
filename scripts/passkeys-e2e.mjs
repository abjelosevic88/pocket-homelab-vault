// Passkeys end to end in a real Chrome, with its virtual authenticator (PRF on):
// add one in Settings → Security, unlock the locked vault with it, then sign
// in from a signed-out page with it (signed in and unlocked, no password).
//
//   DATA_DIR=/tmp/pv DEMO_DATA=true ADMIN_EMAIL=demo@example.com ADMIN_PASSWORD=demodemo1 PORT=18272 BASE_URL=http://localhost:18272 ./pocket-vault
//   CDP=http://127.0.0.1:19271 BASE=http://localhost:18272 node scripts/passkeys-e2e.mjs
// WebAuthn needs a secure context: https, or http://localhost. SHOTS=dir saves screenshots.
import { createRequire } from 'node:module'
import assert from 'node:assert/strict'

const require = createRequire(process.env.PW_FROM || new URL('../web/package.json', import.meta.url))
let pw
try { pw = require('playwright') } catch { pw = require('playwright-core') }
const base = process.env.BASE || 'http://localhost:18272'
const browser = process.env.CDP ? await pw.chromium.connectOverCDP(process.env.CDP) : await pw.chromium.launch()
const MASTER = 'correct horse battery staple'
const errors = []
const shots = process.env.SHOTS

const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 }, deviceScaleFactor: 2, colorScheme: 'dark' })
const page = await ctx.newPage()
page.on('pageerror', e => errors.push(`pageerror: ${e}`))
page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push(m.text()) })
const cdp = await ctx.newCDPSession(page)
await cdp.send('WebAuthn.enable')
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
  protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
  hasPrf: true, automaticPresenceSimulation: true,
} })
const shot = async name => { if (shots) { await page.waitForTimeout(400); await page.screenshot({ path: `${shots}/${name}.png` }) } }

// sign in to Pocket Vault, unlock with the master password
await page.goto(base + '/login')
assert.equal(await page.evaluate(() => fetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'demo@example.com', password: 'demodemo1' }) }).then(r => r.status)), 200)
await page.goto(base + '/', { waitUntil: 'networkidle' })
assert.equal(await page.getByRole('button', { name: /unlock with a passkey/i }).count(), 0, 'no passkey button before one exists')
await page.getByLabel('Master password').fill(MASTER)
await page.getByRole('button', { name: /^unlock$/i }).click()
await page.waitForSelector('.vault-row', { timeout: 30000 })

// add a passkey
await page.evaluate(() => { history.pushState({}, '', '/settings/security'); dispatchEvent(new PopStateEvent('popstate')) })
const card = page.locator('section, .set-section, .card').filter({ has: page.getByRole('heading', { name: 'Passkeys' }) }).last()
await page.getByRole('button', { name: /add a passkey/i }).click()
await card.getByLabel('Name').fill('Test Chrome')
await card.getByLabel('Master password').fill(MASTER)
await card.getByRole('button', { name: /^add passkey$/i }).click()
await page.getByText(/signs in and unlocks your vault/i).first().waitFor({ timeout: 20000 })
await page.getByText('Signs in and unlocks', { exact: false }).first().waitFor()
const creds = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials
assert.equal(creds.length, 1, 'one passkey on the authenticator')
assert.ok(creds[0].isResidentCredential, 'discoverable')
await page.locator('.toast, [role="status"]').first().waitFor({ state: 'detached', timeout: 8000 }).catch(() => {})
await shot('passkeys-settings')

// a reload locks; the passkey unlocks
await page.reload({ waitUntil: 'networkidle' })
await page.goto(base + '/', { waitUntil: 'networkidle' })
const btn = page.getByRole('button', { name: /unlock with a passkey/i })
await btn.waitFor()
await shot('passkeys-lock')
await btn.click()
await page.waitForSelector('.vault-row', { timeout: 30000 })
const items = await page.locator('.vault-row').count()
assert.ok(items > 3, `vault shows items after passkey unlock (${items})`)

// signed out: the sign-in page offers the passkey and lands unlocked
await page.evaluate(() => fetch('/api/v1/auth/logout', { method: 'POST' }))
await page.goto(base + '/login', { waitUntil: 'networkidle' })
const signin = page.getByRole('button', { name: /sign in with a passkey/i })
await signin.waitFor()
await shot('passkeys-login')
await signin.click()
await page.waitForSelector('.vault-row', { timeout: 30000 })
assert.equal(await page.getByLabel('Master password').count(), 0, 'no master password asked')

// activity shows it
const ev = await page.evaluate(() => fetch('/api/v1/vault/status').then(r => r.json()))
assert.equal(ev.passkeys, 1)
assert.equal(ev.passkeys_unlock, 1)

await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId })
await ctx.close()
await browser.close()
if (errors.length) { console.error(errors.join('\n')); process.exit(1) }
console.log(`passkeys e2e ok (${items} items unlocked with a passkey)`)
