-- Passkeys that sign in to a vault (Bitwarden's "log in with passkey").
-- A passkey with the PRF extension also unlocks: the browser derives a key
-- from it that only that passkey can make again; that key opens
-- encrypted_private_key, which opens encrypted_user_key. The server holds
-- only these wrapped keys and the passkey's public key.
CREATE TABLE vault_passkeys (
  user_id               INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  uuid                  TEXT NOT NULL UNIQUE,
  name                  TEXT NOT NULL DEFAULT '',
  credential_id         TEXT NOT NULL UNIQUE,          -- base64url, what the authenticator names it
  credential            TEXT NOT NULL,                 -- JSON: public key, flags, sign count
  supports_prf          INTEGER NOT NULL DEFAULT 0,
  encrypted_user_key    TEXT NOT NULL DEFAULT '',      -- "4.…" the user key, RSA-wrapped with the passkey's public key
  encrypted_public_key  TEXT NOT NULL DEFAULT '',      -- that public key, encrypted with the user key
  encrypted_private_key TEXT NOT NULL DEFAULT '',      -- its private key, encrypted with the key from the passkey
  last_used_at          TEXT,
  created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX vault_passkeys_user ON vault_passkeys(user_id);
