# Configuration

Environment variables; every one has a default. Personal settings (locking, notifications, connections) live in the UI per person — `NOTIFY_*` below is copied once into the first admin's settings.

| Variable | Default | What |
|---|---|---|
| `PORT`, `HOST` | `8080`, `0.0.0.0` | Listen address |
| `BASE_URL` | – | The public address. The Bitwarden apps use it as the server URL (they need **HTTPS**); it is also the token issuer, so it must not change once apps are signed in (a move from Vaultwarden keeps the same one) |
| `DATA_DIR` | `./data` | Database, `rsa_key.pem` (signs the apps' tokens), icon cache, Core token, backups |
| `DB_PATH` | `$DATA_DIR/pocket-vault.db` | SQLite file |
| `MAX_BODY_BYTES` | `67108864` | Largest request (an import) |
| `AUTH_MODE` | `local` | Sign-in to the Pocket Vault web app: `local` (accounts), `proxy` (trust `AUTH_PROXY_HEADER`/`AUTH_PROXY_EMAIL_HEADER`), `none`. The vault itself always needs the master password |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME` | – | Seed the first admin while the database is empty |
| `SESSION_TTL`, `SECURE_COOKIES` | `720h`, `false` | Set `SECURE_COOKIES=true` behind HTTPS |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_NAME`, `OIDC_AUTO_CREATE` | – | Sign in with an OpenID Connect provider (not needed with Pocket Core) |
| `NOTIFY_URL`, `NOTIFY_FORMAT` | – | Apprise (`…/notify/key`), ntfy topic URL or JSON webhook; format `apprise`/`ntfy`/`json` |
| `ACCESS_TOKEN_TTL` | `2h` | How long an app's access token lives (it renews itself; refresh tokens last 30 days, 90 on phones) |
| `LOGIN_ATTEMPTS` | `10` | Wrong master passwords per address and 10 minutes before a pause (0 = no limit) |
| `ICON_SERVICE` | `internal` | Website icons: `internal` (this server fetches the site's favicon, public addresses only), `duckduckgo`, `google`, `off` |
| `ICON_CACHE_TTL` | `720h` | How long a fetched icon is kept |
| `GLOBAL_DOMAINS_FILE` | – | Bitwarden's list of sites that share logins (google.com ≈ youtube.com…), for autofill matching in the apps — e.g. Vaultwarden's `src/static/global_domains.json`. Without it only your own domain rules apply |
| `BIN_DAYS` | `0` | Delete items that have been in the bin this many days (0 = keep them, like Vaultwarden; Bitwarden's cloud uses 30) |
| `CORE_URL`, `CORE_REGISTRATION_KEY`, `CORE_APP_URL` | – | Pocket Core |
| `TRUST_PROXY`, `METRICS_ENABLED`, `LOG_LEVEL`, `LOG_FORMAT` | `true`, `true`, `info`, `text` | `TRUST_PROXY` takes the client address from `X-Forwarded-For` (sign-in limits and the activity list) — keep the port private when it is on |
| `DEMO_DATA` | `false` | Give the owner a demo vault (master password `correct horse battery staple`) |

Commands: `pocket-vault import-vaultwarden -dir VW_DATA [-replace] [-email ONE] [-no-key]`, `pocket-vault backup [-o FILE]`, `pocket-vault reset-password [-email] [-password]` (the web sign-in, not the master password), `pocket-vault version`.
