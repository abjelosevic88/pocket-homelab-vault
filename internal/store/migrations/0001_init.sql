CREATE TABLE users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  role          TEXT NOT NULL DEFAULT 'member',
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at    TEXT
);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE api_tokens (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL DEFAULT '',
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL DEFAULT '',
  last_used_at TEXT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Box-wide settings (title, setup flag); everything else is personal.
CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE user_settings (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key     TEXT NOT NULL,
  value   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (user_id, key)
);

CREATE TABLE cache (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL DEFAULT '',
  fetched_at TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- The vault. Everything below is a Bitwarden-compatible account: the apps
-- (browser extension, phone, desktop, CLI) encrypt on the device, so the
-- server only ever stores encrypted text ("2.iv|data|mac") and cannot read
-- a name, a username or a password. Ids are the UUIDs the apps know.

-- One vault per person (Pocket user). The email is the Bitwarden login and
-- the salt of the master key, so it never changes here.
CREATE TABLE vault_accounts (
  user_id            INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  uuid               TEXT NOT NULL UNIQUE,
  email              TEXT NOT NULL UNIQUE,         -- lowercase
  name               TEXT NOT NULL DEFAULT '',
  master_hash        BLOB NOT NULL,                -- PBKDF2-SHA256 of the hash the app sends
  master_salt        BLOB NOT NULL,
  master_iterations  INTEGER NOT NULL DEFAULT 600000,
  password_hint      TEXT NOT NULL DEFAULT '',
  akey               TEXT NOT NULL DEFAULT '',     -- the user key, encrypted with the master key
  private_key        TEXT NOT NULL DEFAULT '',     -- encrypted with the user key
  public_key         TEXT NOT NULL DEFAULT '',
  security_stamp     TEXT NOT NULL,
  stamp_exception    TEXT NOT NULL DEFAULT '',
  kdf_type           INTEGER NOT NULL DEFAULT 0,   -- 0 PBKDF2, 1 Argon2id
  kdf_iterations     INTEGER NOT NULL DEFAULT 600000,
  kdf_memory         INTEGER,
  kdf_parallelism    INTEGER,
  totp_recover       TEXT NOT NULL DEFAULT '',
  equivalent_domains TEXT NOT NULL DEFAULT '[]',
  excluded_globals   TEXT NOT NULL DEFAULT '[]',
  avatar_color       TEXT,
  api_key            TEXT NOT NULL DEFAULT '',
  enabled            INTEGER NOT NULL DEFAULT 1,
  user_key_id        TEXT NOT NULL DEFAULT '',     -- the id newer apps give the user key (not key material)
  revision_date      TEXT NOT NULL,                -- bumped on every change; apps compare it to decide to sync
  created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- A signed-in app. uuid = the app's own device identifier.
CREATE TABLE vault_devices (
  user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  uuid               TEXT NOT NULL,
  name               TEXT NOT NULL DEFAULT '',
  type               INTEGER NOT NULL DEFAULT 14,
  push_token         TEXT NOT NULL DEFAULT '',
  push_uuid          TEXT NOT NULL DEFAULT '',
  refresh_token      TEXT NOT NULL UNIQUE,
  twofactor_remember TEXT NOT NULL DEFAULT '',
  last_ip            TEXT NOT NULL DEFAULT '',
  client_id          TEXT NOT NULL DEFAULT '',
  created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (user_id, uuid)
);

CREATE TABLE vault_folders (
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  uuid       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,                         -- encrypted
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX vault_folders_user ON vault_folders(user_id);

-- An item. type: 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key
-- (6 bank account, 7 driver's licence, 8 passport on the newest apps).
-- data is the type's own object as the app sent it, kept whole so fields
-- added by newer apps (passkeys…) survive.
CREATE TABLE vault_ciphers (
  user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  uuid             TEXT NOT NULL UNIQUE,
  type             INTEGER NOT NULL,
  folder_uuid      TEXT,
  favorite         INTEGER NOT NULL DEFAULT 0,
  key              TEXT,                            -- the item's own key, encrypted with the user key
  name             TEXT NOT NULL DEFAULT '',
  notes            TEXT,
  fields           TEXT,                            -- JSON
  data             TEXT NOT NULL DEFAULT '{}',      -- JSON
  password_history TEXT,                            -- JSON
  reprompt         INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at       TEXT,
  archived_at      TEXT
);
CREATE INDEX vault_ciphers_user ON vault_ciphers(user_id, deleted_at);

-- Two-step login. type: 0 authenticator app (data = base32 secret).
CREATE TABLE vault_twofactor (
  user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type      INTEGER NOT NULL,
  enabled   INTEGER NOT NULL DEFAULT 1,
  data      TEXT NOT NULL DEFAULT '',
  last_used INTEGER NOT NULL DEFAULT 0,             -- the last TOTP time step used (no replays)
  PRIMARY KEY (user_id, type)
);

-- What happened to a vault: sign-ins, failed tries, changes to security.
-- Shown under Devices & activity; never holds item data.
CREATE TABLE vault_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,                        -- signed_in | new_device | signin_failed | twofactor_failed | twofactor_on | twofactor_off | password_changed | kdf_changed | device_removed | signed_out_everywhere | imported | export
  device_name TEXT NOT NULL DEFAULT '',
  device_type INTEGER,
  ip          TEXT NOT NULL DEFAULT '',
  detail      TEXT NOT NULL DEFAULT '',
  at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX vault_events_user ON vault_events(user_id, at);

-- The health summary a person chose to share with their other Pocket apps:
-- numbers worked out in their browser, never names or passwords.
CREATE TABLE vault_health (
  user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  summary    TEXT NOT NULL DEFAULT '{}',            -- JSON: counts only
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Reminders sent to Pocket Renewals from an item (card or document expiry),
-- so the same item is not sent twice.
CREATE TABLE vault_reminders (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cipher_uuid TEXT NOT NULL,
  renewal_id  INTEGER NOT NULL DEFAULT 0,
  title       TEXT NOT NULL DEFAULT '',
  expires_on  TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (user_id, cipher_uuid)
);
