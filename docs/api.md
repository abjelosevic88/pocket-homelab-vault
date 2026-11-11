# API

Pocket Vault speaks two APIs.

## The Bitwarden API

What the Bitwarden apps and `bw` use, at `BASE_URL`: `/identity/connect/token` (password, passkey (`grant_type=webauthn`) and refresh sign-in, two-step login), `/identity/accounts/prelogin`, `/identity/accounts/webauthn/assertion-options`, `/api/config`, `/api/sync`, `/api/ciphers…` (create, edit, partial, move, bin, restore, archive, import, purge), `/api/folders…`, `/api/accounts…` (profile, keys, password, KDF, security stamp, revision date, verify password), `/api/devices…`, `/api/two-factor…` (authenticator app, recovery code), `/api/webauthn…` (passkeys that sign in and, with PRF, unlock: list, attestation-options, add, assertion-options, update keys, delete), `/api/settings/domains`, `/notifications/hub` (SignalR over websocket, MessagePack) and `/icons/<domain>/icon.png`. It answers as Bitwarden server 2026.6.0 — the same responses Vaultwarden gives, field for field — so the apps' newest features (per-item keys, passkeys, archive, SSH keys) work.

Not there yet, and answered as empty lists or a plain error: organisations and sharing, attachments, Send, emergency access, sign-in with another device, SSO, API keys.

## The Pocket API

This app's own API at `/api/v1`, with a session cookie or `Authorization: Bearer <token>` (Settings → API & shortcuts, or a Pocket Core link). None of it returns an item: they need the master password.

| | |
|---|---|
| `GET /vault/status` | Has a vault? Email, KDF, counts, signed-in apps, two-step login, hint |
| `POST /vault/setup` | Create your vault from keys made in the browser: `{master_password_hash, key, public_key, private_key, kdf_type, kdf_iterations, hint}` |
| `DELETE /vault` | `{master_password_hash}` — delete your vault |
| `GET /vault/overview` | Counts, apps, two-step login, recent sign-ins and the shared health numbers — what other apps may read (`vault:read`) |
| `GET /vault/activity?limit=` | Sign-ins, wrong tries, security changes |
| `GET /vault/devices`, `DELETE /vault/devices/{id}` | Signed-in apps; sign one out |
| `POST /vault/sign-out-everywhere` | New security stamp and refresh tokens: every app signs in again |
| `PUT /vault/health` | The health numbers the browser worked out (stored only when you share them) |
| `GET/POST /vault/reminders`, `DELETE /vault/reminders/{cipher}` | Expiry reminders sent to Pocket Renewals |
| `POST /vault/import/vaultwarden` | Admin: multipart `db` (+ `wal`, `key`, `replace`) |
| `GET/PUT /settings`, `GET /settings/system` | Your settings; the server |
| `GET /backup` | Admin: the whole database |

## Pocket Core

Offers `vault:read` (only `GET /vault/overview`). Publishes `vault.created`, `vault.device_signed_in`, `vault.signin_failed` and `vault.security_changed` — none carries item data. Uses Pocket Renewals (`renewals:write`) for "remind me before it expires".
