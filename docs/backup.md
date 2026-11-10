# Backup

Two files matter in `DATA_DIR`:

- `pocket-vault.db` — every account and its encrypted items (WAL mode). Take a consistent copy with `pocket-vault backup` (writes `DATA_DIR/backups/pocket-vault-<time>.db` with `VACUUM INTO`) or Settings → Backup & data → Download database (admin). Back up that copy, not the live file.
- `rsa_key.pem` — signs the apps' tokens. Without it a restored server still works, but every app signs in again.

Items in the database stay encrypted with each person's own key: a backup is useless without their master password, and so is a stolen one.

Restore: stop the app, replace `pocket-vault.db` (remove `-wal`/`-shm` files) and `rsa_key.pem`, start.

Each person can also export their vault from the web app (Settings → Backup & data): Bitwarden's encrypted JSON (opens only with that vault's key) or readable JSON. `DATA_DIR/icons/` is a cache and needn't be backed up.
