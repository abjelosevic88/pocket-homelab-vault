# Reverse proxy

Set `BASE_URL` to the public HTTPS address and `SECURE_COOKIES=true`. See [deploy/reverse-proxy/Caddyfile](../deploy/reverse-proxy/Caddyfile).

What has to reach the app:

- `/identity/*`, `/api/*` — the Bitwarden apps (sign-in, sync, items) and this app's own `/api/v1`.
- `/notifications/hub` — a websocket for live sync (browser extension, desktop). Caddy passes it as it is; with nginx add `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";`.
- `/icons/<domain>/icon.png` — website icons.

Pass the real client address (`X-Forwarded-For`): it is what the sign-in limit counts and what the activity list shows. Don't expose the app's port directly when `TRUST_PROXY` is on.
