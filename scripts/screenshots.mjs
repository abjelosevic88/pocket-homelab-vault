// README screenshots and a browser smoke test, against a demo instance (DEMO_DATA=true seeds a vault whose master
// password is "correct horse battery staple"):
//
//   DATA_DIR=/tmp/vault-demo DEMO_DATA=true ADMIN_EMAIL=demo@example.com ADMIN_PASSWORD=demodemo1 ADMIN_NAME=Alex PORT=18271 ./pocket-vault
//   CDP=http://127.0.0.1:19271 BASE=http://127.0.0.1:18271 node scripts/screenshots.mjs   # any Chrome with remote debugging
//   SHOTS=0 … node scripts/screenshots.mjs                                                  # checks only
// playwright-core comes from web/node_modules, or set PW_FROM to a package.json next to an install of it.
import { createRequire } from 'node:module'
import assert from 'node:assert/strict'

const require = createRequire(process.env.PW_FROM || new URL('../web/package.json', import.meta.url))
let pw
try { pw = require('playwright') } catch { pw = require('playwright-core') }
const { chromium } = pw
const base = process.env.BASE || 'http://127.0.0.1:18271'
const shots = process.env.SHOTS !== '0'
const dir = new URL('../docs/screenshots/', import.meta.url).pathname
const browser = process.env.CDP ? await chromium.connectOverCDP(process.env.CDP) : await chromium.launch()
const errors = []
const MASTER = 'correct horse battery staple'

async function session({ phone = false, dark = false } = {}) {
  const ctx = await browser.newContext({
    viewport: phone ? { width: 390, height: 844 } : { width: 1440, height: 900 },
    deviceScaleFactor: phone ? 3 : 2, isMobile: phone, hasTouch: phone, colorScheme: dark ? 'dark' : 'light',
    userAgent: phone ? 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1' : undefined,
  })
  const page = await ctx.newPage()
  page.on('pageerror', e => errors.push(`pageerror: ${e}`))
  page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push(m.text()) })
  await page.goto(base + '/login')
  const res = await page.evaluate(() => fetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'demo@example.com', password: 'demodemo1' }) }).then(r => r.status))
  assert.equal(res, 200, 'demo sign-in')
  return { ctx, page }
}
async function settle(page, wait = 900) {
  await page.addStyleTag({ content: '*, *::before, *::after { transition: none !important; animation: none !important; }' })
  await page.evaluate(() => document.fonts.ready)
  await page.waitForTimeout(wait)
}
async function unlock(page) {
  await page.goto(base + '/', { waitUntil: 'networkidle' })
  await page.getByLabel('Master password').fill(MASTER)
  await page.getByRole('button', { name: /unlock/i }).click()
  await page.waitForSelector('.vault-row', { timeout: 30000 })
}
/** In-app navigation (a full reload would lock the vault, as it should). */
async function nav(page, path, wait) {
  await page.evaluate(p => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')) }, path)
  await settle(page, wait)
}
// headless Chrome can't capture a blurred modal backdrop at 2x (and the page
// stops answering after it tries): dialogs are taken at 1x
async function shot(page, name, modal = false) { if (shots) await page.screenshot({ path: dir + name + '.png', ...(modal ? { scale: 'css' } : {}) }) }

// ---- desktop ----
{
  const { ctx, page } = await session()
  await page.goto(base + '/', { waitUntil: 'networkidle' })
  await settle(page, 600)
  assert.ok(await page.getByText('Your vault is locked').isVisible(), 'a fresh tab is locked')
  await shot(page, 'desktop-locked')
  await unlock(page)
  const rows = await page.locator('.vault-row').count()
  assert.ok(rows >= 30, `the demo vault lists its items (${rows})`)
  await page.getByRole('option', { name: 'GitHub alex.dev' }).click()
  await settle(page, 1500)
  assert.ok(await page.locator('.totp').isVisible(), 'a login with an authenticator key shows a live code')
  await shot(page, 'desktop-vault')
  await page.locator('.vault-row', { hasText: 'Northwind Visa' }).click()
  await settle(page)
  await shot(page, 'desktop-card')
  await nav(page, '/health', 1200)
  assert.ok(await page.locator('.health-score').isVisible(), 'health has a score')
  await shot(page, 'desktop-health')
  await nav(page, '/generator', 900)
  await shot(page, 'desktop-generator')
  await nav(page, '/activity', 1200)
  assert.ok((await page.locator('.dev-row').count()) >= 4, 'signed-in apps are listed')
  await shot(page, 'desktop-activity')
  await nav(page, '/apps', 800)
  await shot(page, 'desktop-apps')
  // a new login, with a generated password
  await nav(page, '/', 500)
  await page.keyboard.press('n')
  await settle(page, 500)
  await page.locator('.item-form input').first().fill('Example shop')
  await page.getByRole('button', { name: 'Generate a password' }).click()
  await settle(page, 400)
  await shot(page, 'desktop-new', true)
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await page.waitForSelector('.item-head h2:has-text("Example shop")', { timeout: 15000 })
  await ctx.close()
}

// ---- dark ----
{
  const { ctx, page } = await session({ dark: true })
  await unlock(page)
  await page.locator('.vault-row', { hasText: 'Alex Morgan' }).click()
  await settle(page)
  await shot(page, 'desktop-dark')
  await ctx.close()
}

// ---- phone ----
{
  const { ctx, page } = await session({ phone: true })
  await unlock(page)
  await settle(page)
  await shot(page, 'phone-vault')
  await page.locator('.vault-row', { hasText: 'Google' }).first().click()
  await settle(page, 1200)
  await shot(page, 'phone-item')
  await nav(page, '/health', 1000)
  await shot(page, 'phone-health')
  await ctx.close()
}

await browser.close()
if (errors.length) { console.error(errors.join('\n')); process.exit(1) }
console.log('ok')
