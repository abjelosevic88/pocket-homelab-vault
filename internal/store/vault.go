package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// BWTime is how the Bitwarden apps write dates: RFC 3339, UTC, microseconds.
const BWTime = "2006-01-02T15:04:05.000000Z"

// BWNow is the current time in the Bitwarden form.
func BWNow() string { return time.Now().UTC().Format(BWTime) }

// BWDate turns any stored date (RFC 3339 or SQLite's "2006-01-02 15:04:05")
// into the Bitwarden form; "" stays "".
func BWDate(s string) string {
	if s == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(BWTime)
		}
	}
	return s
}

// VaultAccount is one person's Bitwarden-compatible account.
type VaultAccount struct {
	UserID            int64
	UUID              string
	Email             string
	Name              string
	MasterHash        []byte
	MasterSalt        []byte
	MasterIterations  int
	PasswordHint      string
	AKey              string
	PrivateKey        string
	PublicKey         string
	SecurityStamp     string
	StampException    string
	KdfType           int
	KdfIterations     int
	KdfMemory         *int
	KdfParallelism    *int
	TotpRecover       string
	EquivalentDomains string
	ExcludedGlobals   string
	AvatarColor       *string
	APIKey            string
	Enabled           bool
	RevisionDate      string
	CreatedAt         string
	UpdatedAt         string
}

const accountCols = `user_id, uuid, email, name, master_hash, master_salt, master_iterations, password_hint, akey, private_key, public_key,
	security_stamp, stamp_exception, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, totp_recover, equivalent_domains, excluded_globals,
	avatar_color, api_key, enabled, revision_date, created_at, updated_at`

func scanAccount(row interface{ Scan(...any) error }) (*VaultAccount, error) {
	a := &VaultAccount{}
	var mem, par sql.NullInt64
	var avatar sql.NullString
	var enabled int
	err := row.Scan(&a.UserID, &a.UUID, &a.Email, &a.Name, &a.MasterHash, &a.MasterSalt, &a.MasterIterations, &a.PasswordHint, &a.AKey, &a.PrivateKey, &a.PublicKey,
		&a.SecurityStamp, &a.StampException, &a.KdfType, &a.KdfIterations, &mem, &par, &a.TotpRecover, &a.EquivalentDomains, &a.ExcludedGlobals,
		&avatar, &a.APIKey, &enabled, &a.RevisionDate, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	if mem.Valid {
		v := int(mem.Int64)
		a.KdfMemory = &v
	}
	if par.Valid {
		v := int(par.Int64)
		a.KdfParallelism = &v
	}
	if avatar.Valid {
		a.AvatarColor = &avatar.String
	}
	a.Enabled = enabled != 0
	return a, nil
}

func intPtr(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func strPtr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// GetVaultAccount returns a person's vault.
func (s *Store) GetVaultAccount(ctx context.Context, uid int64) (*VaultAccount, error) {
	return scanAccount(s.DB.QueryRowContext(ctx, `SELECT `+accountCols+` FROM vault_accounts WHERE user_id = ?`, uid))
}

// GetVaultAccountByEmail finds a vault by its login email.
func (s *Store) GetVaultAccountByEmail(ctx context.Context, email string) (*VaultAccount, error) {
	return scanAccount(s.DB.QueryRowContext(ctx, `SELECT `+accountCols+` FROM vault_accounts WHERE email = ?`, strings.ToLower(strings.TrimSpace(email))))
}

// GetVaultAccountByUUID finds a vault by the id the apps know.
func (s *Store) GetVaultAccountByUUID(ctx context.Context, uuid string) (*VaultAccount, error) {
	return scanAccount(s.DB.QueryRowContext(ctx, `SELECT `+accountCols+` FROM vault_accounts WHERE uuid = ?`, strings.ToLower(uuid)))
}

// CreateVaultAccount inserts a vault (the account must not exist yet).
func (s *Store) CreateVaultAccount(ctx context.Context, a *VaultAccount) error {
	now := BWNow()
	if a.RevisionDate == "" {
		a.RevisionDate = now
	}
	if a.CreatedAt == "" {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))
	if a.EquivalentDomains == "" {
		a.EquivalentDomains = "[]"
	}
	if a.ExcludedGlobals == "" {
		a.ExcludedGlobals = "[]"
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO vault_accounts (`+accountCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.UserID, a.UUID, a.Email, a.Name, a.MasterHash, a.MasterSalt, a.MasterIterations, a.PasswordHint, a.AKey, a.PrivateKey, a.PublicKey,
		a.SecurityStamp, a.StampException, a.KdfType, a.KdfIterations, intPtr(a.KdfMemory), intPtr(a.KdfParallelism), a.TotpRecover, a.EquivalentDomains, a.ExcludedGlobals,
		strPtr(a.AvatarColor), a.APIKey, boolInt(a.Enabled), a.RevisionDate, a.CreatedAt, a.UpdatedAt)
	return conflict(err)
}

// SaveVaultAccount writes every changeable field and bumps the revision date.
func (s *Store) SaveVaultAccount(ctx context.Context, a *VaultAccount) error {
	now := BWNow()
	a.UpdatedAt, a.RevisionDate = now, now
	res, err := s.DB.ExecContext(ctx, `UPDATE vault_accounts SET name=?, master_hash=?, master_salt=?, master_iterations=?, password_hint=?, akey=?, private_key=?, public_key=?,
		security_stamp=?, stamp_exception=?, kdf_type=?, kdf_iterations=?, kdf_memory=?, kdf_parallelism=?, totp_recover=?, equivalent_domains=?, excluded_globals=?,
		avatar_color=?, api_key=?, enabled=?, revision_date=?, updated_at=? WHERE user_id = ?`,
		a.Name, a.MasterHash, a.MasterSalt, a.MasterIterations, a.PasswordHint, a.AKey, a.PrivateKey, a.PublicKey,
		a.SecurityStamp, a.StampException, a.KdfType, a.KdfIterations, intPtr(a.KdfMemory), intPtr(a.KdfParallelism), a.TotpRecover, a.EquivalentDomains, a.ExcludedGlobals,
		strPtr(a.AvatarColor), a.APIKey, boolInt(a.Enabled), a.RevisionDate, a.UpdatedAt, a.UserID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchVault bumps a vault's revision date (any item or folder changed) and
// returns it, so apps know to sync.
func (s *Store) TouchVault(ctx context.Context, uid int64) string {
	now := BWNow()
	_, _ = s.DB.ExecContext(ctx, `UPDATE vault_accounts SET revision_date = ? WHERE user_id = ?`, now, uid)
	return now
}

// DeleteVault removes a person's vault and everything in it (not their Pocket account).
func (s *Store) DeleteVault(ctx context.Context, uid int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, t := range []string{"vault_ciphers", "vault_folders", "vault_devices", "vault_twofactor", "vault_health", "vault_reminders", "vault_passkeys", "vault_accounts"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE user_id = ?`, uid); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// UserKeyID is the id newer apps recorded for the user key ("" = none).
func (s *Store) UserKeyID(ctx context.Context, uid int64) string {
	var id string
	_ = s.DB.QueryRowContext(ctx, `SELECT user_key_id FROM vault_accounts WHERE user_id = ?`, uid).Scan(&id)
	return id
}

// SetUserKeyID records the user key's id.
func (s *Store) SetUserKeyID(ctx context.Context, uid int64, id string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE vault_accounts SET user_key_id = ?, revision_date = ? WHERE user_id = ?`, id, BWNow(), uid)
	return err
}

// ---- devices ----

// Device is a signed-in app.
type Device struct {
	UserID            int64
	UUID              string
	Name              string
	Type              int
	PushToken         string
	PushUUID          string
	RefreshToken      string
	TwoFactorRemember string
	LastIP            string
	ClientID          string
	CreatedAt         string
	UpdatedAt         string
}

const deviceCols = `user_id, uuid, name, type, push_token, push_uuid, refresh_token, twofactor_remember, last_ip, client_id, created_at, updated_at`

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	d := &Device{}
	if err := row.Scan(&d.UserID, &d.UUID, &d.Name, &d.Type, &d.PushToken, &d.PushUUID, &d.RefreshToken, &d.TwoFactorRemember, &d.LastIP, &d.ClientID, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, notFound(err)
	}
	return d, nil
}

// GetDevice returns one of a person's devices.
func (s *Store) GetDevice(ctx context.Context, uid int64, uuid string) (*Device, error) {
	return scanDevice(s.DB.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM vault_devices WHERE user_id = ? AND uuid = ?`, uid, uuid))
}

// GetDeviceByRefreshToken finds the device a refresh token belongs to.
func (s *Store) GetDeviceByRefreshToken(ctx context.Context, tok string) (*Device, error) {
	if tok == "" {
		return nil, ErrNotFound
	}
	return scanDevice(s.DB.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM vault_devices WHERE refresh_token = ?`, tok))
}

// SaveDevice inserts or updates a device; touch moves updated_at to now.
func (s *Store) SaveDevice(ctx context.Context, d *Device, touch bool) error {
	now := BWNow()
	if d.CreatedAt == "" {
		d.CreatedAt = now
	}
	if touch || d.UpdatedAt == "" {
		d.UpdatedAt = now
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO vault_devices (`+deviceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(user_id, uuid) DO UPDATE SET name=excluded.name, type=excluded.type, push_token=excluded.push_token, push_uuid=excluded.push_uuid,
		refresh_token=excluded.refresh_token, twofactor_remember=excluded.twofactor_remember, last_ip=excluded.last_ip, client_id=excluded.client_id, updated_at=excluded.updated_at`,
		d.UserID, d.UUID, d.Name, d.Type, d.PushToken, d.PushUUID, d.RefreshToken, d.TwoFactorRemember, d.LastIP, d.ClientID, d.CreatedAt, d.UpdatedAt)
	return conflict(err)
}

// ListDevices lists a person's signed-in apps, most recently used first.
func (s *Store) ListDevices(ctx context.Context, uid int64) ([]Device, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+deviceCols+` FROM vault_devices WHERE user_id = ? ORDER BY updated_at DESC`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// DeleteDevice signs one app out for good (its refresh token stops working).
func (s *Store) DeleteDevice(ctx context.Context, uid int64, uuid string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM vault_devices WHERE user_id = ? AND uuid = ?`, uid, uuid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RotateRefreshTokens gives every device of a person a new refresh token, so
// the ones the apps hold stop working (after a master password change).
func (s *Store) RotateRefreshTokens(ctx context.Context, uid int64) error {
	devs, err := s.ListDevices(ctx, uid)
	if err != nil {
		return err
	}
	for _, d := range devs {
		if _, err := s.DB.ExecContext(ctx, `UPDATE vault_devices SET refresh_token = ?, twofactor_remember = '' WHERE user_id = ? AND uuid = ?`, RandomToken(48), uid, d.UUID); err != nil {
			return err
		}
	}
	return nil
}

// ---- folders ----

// Folder is a person's folder (the name is encrypted).
type Folder struct {
	UserID    int64
	UUID      string
	Name      string
	CreatedAt string
	UpdatedAt string
}

// ListFolders lists a person's folders.
func (s *Store) ListFolders(ctx context.Context, uid int64) ([]Folder, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT user_id, uuid, name, created_at, updated_at FROM vault_folders WHERE user_id = ? ORDER BY created_at`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Folder{}
	for rows.Next() {
		var f Folder
		if err := rows.Scan(&f.UserID, &f.UUID, &f.Name, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetFolder returns one of a person's folders.
func (s *Store) GetFolder(ctx context.Context, uid int64, uuid string) (*Folder, error) {
	f := &Folder{}
	err := s.DB.QueryRowContext(ctx, `SELECT user_id, uuid, name, created_at, updated_at FROM vault_folders WHERE user_id = ? AND uuid = ?`, uid, uuid).
		Scan(&f.UserID, &f.UUID, &f.Name, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return f, nil
}

// SaveFolder inserts or updates a folder (refusing someone else's uuid).
func (s *Store) SaveFolder(ctx context.Context, f *Folder) error {
	now := BWNow()
	if f.CreatedAt == "" {
		f.CreatedAt = now
	}
	f.UpdatedAt = now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO vault_folders (user_id, uuid, name, created_at, updated_at) VALUES (?,?,?,?,?)
		ON CONFLICT(uuid) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at WHERE vault_folders.user_id = excluded.user_id`,
		f.UserID, f.UUID, f.Name, f.CreatedAt, f.UpdatedAt)
	if err != nil {
		return conflict(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	return nil
}

// DeleteFolder removes a folder; its items move to "no folder".
func (s *Store) DeleteFolder(ctx context.Context, uid int64, uuid string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM vault_folders WHERE user_id = ? AND uuid = ?`, uid, uuid)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE vault_ciphers SET folder_uuid = NULL WHERE user_id = ? AND folder_uuid = ?`, uid, uuid); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- items (ciphers) ----

// Cipher is one vault item. Everything but the type, the folder, the
// favourite mark and the dates is encrypted by the app.
type Cipher struct {
	UserID          int64
	UUID            string
	Type            int
	FolderUUID      *string
	Favorite        bool
	Key             *string
	Name            string
	Notes           *string
	Fields          *string
	Data            string
	PasswordHistory *string
	Reprompt        int
	CreatedAt       string
	UpdatedAt       string
	DeletedAt       *string
	ArchivedAt      *string
}

const cipherCols = `user_id, uuid, type, folder_uuid, favorite, key, name, notes, fields, data, password_history, reprompt, created_at, updated_at, deleted_at, archived_at`

func scanCipher(row interface{ Scan(...any) error }) (*Cipher, error) {
	c := &Cipher{}
	var folder, key, notes, fields, hist, deleted, archived sql.NullString
	var fav int
	if err := row.Scan(&c.UserID, &c.UUID, &c.Type, &folder, &fav, &key, &c.Name, &notes, &fields, &c.Data, &hist, &c.Reprompt, &c.CreatedAt, &c.UpdatedAt, &deleted, &archived); err != nil {
		return nil, notFound(err)
	}
	ns := func(v sql.NullString) *string {
		if !v.Valid {
			return nil
		}
		s := v.String
		return &s
	}
	c.FolderUUID, c.Key, c.Notes, c.Fields, c.PasswordHistory, c.DeletedAt, c.ArchivedAt = ns(folder), ns(key), ns(notes), ns(fields), ns(hist), ns(deleted), ns(archived)
	c.Favorite = fav != 0
	return c, nil
}

// ListCiphers lists all of a person's items, the bin included.
func (s *Store) ListCiphers(ctx context.Context, uid int64) ([]Cipher, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+cipherCols+` FROM vault_ciphers WHERE user_id = ? ORDER BY created_at`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Cipher{}
	for rows.Next() {
		c, err := scanCipher(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetCipher returns one of a person's items.
func (s *Store) GetCipher(ctx context.Context, uid int64, uuid string) (*Cipher, error) {
	return scanCipher(s.DB.QueryRowContext(ctx, `SELECT `+cipherCols+` FROM vault_ciphers WHERE user_id = ? AND uuid = ?`, uid, strings.ToLower(uuid)))
}

// SaveCipher inserts or updates an item; keepDate leaves updated_at as set
// (imports), otherwise it becomes now.
func (s *Store) SaveCipher(ctx context.Context, c *Cipher, keepDate bool) error {
	now := BWNow()
	if c.CreatedAt == "" {
		c.CreatedAt = now
	}
	if !keepDate || c.UpdatedAt == "" {
		c.UpdatedAt = now
	}
	if c.Data == "" {
		c.Data = "{}"
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO vault_ciphers (`+cipherCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(uuid) DO UPDATE SET type=excluded.type, folder_uuid=excluded.folder_uuid, favorite=excluded.favorite, key=excluded.key, name=excluded.name,
		notes=excluded.notes, fields=excluded.fields, data=excluded.data, password_history=excluded.password_history, reprompt=excluded.reprompt,
		updated_at=excluded.updated_at, deleted_at=excluded.deleted_at, archived_at=excluded.archived_at WHERE vault_ciphers.user_id = excluded.user_id`,
		c.UserID, strings.ToLower(c.UUID), c.Type, strPtr(c.FolderUUID), boolInt(c.Favorite), strPtr(c.Key), c.Name, strPtr(c.Notes), strPtr(c.Fields), c.Data,
		strPtr(c.PasswordHistory), c.Reprompt, c.CreatedAt, c.UpdatedAt, strPtr(c.DeletedAt), strPtr(c.ArchivedAt))
	if err != nil {
		return conflict(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict // the uuid belongs to someone else
	}
	return nil
}

// DeleteCipher removes an item for good.
func (s *Store) DeleteCipher(ctx context.Context, uid int64, uuid string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM vault_ciphers WHERE user_id = ? AND uuid = ?`, uid, strings.ToLower(uuid))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeVault deletes every item and folder of a person.
func (s *Store) PurgeVault(ctx context.Context, uid int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM vault_ciphers WHERE user_id = ?`, `DELETE FROM vault_folders WHERE user_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, uid); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// EmptyBin removes items that have been in the bin for longer than d.
func (s *Store) EmptyBin(ctx context.Context, d time.Duration) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM vault_ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?`, time.Now().UTC().Add(-d).Format(BWTime))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// VaultCounts is how many items of each type a person has (bin excluded).
func (s *Store) VaultCounts(ctx context.Context, uid int64) (map[string]int, error) {
	out := map[string]int{"items": 0, "logins": 0, "notes": 0, "cards": 0, "identities": 0, "ssh_keys": 0, "other": 0, "folders": 0, "bin": 0, "favorites": 0}
	rows, err := s.DB.QueryContext(ctx, `SELECT type, deleted_at IS NOT NULL, favorite, COUNT(1) FROM vault_ciphers WHERE user_id = ? GROUP BY 1, 2, 3`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := map[int]string{1: "logins", 2: "notes", 3: "cards", 4: "identities", 5: "ssh_keys"}
	for rows.Next() {
		var t, del, fav, n int
		if err := rows.Scan(&t, &del, &fav, &n); err != nil {
			return nil, err
		}
		if del == 1 {
			out["bin"] += n
			continue
		}
		out["items"] += n
		if fav == 1 {
			out["favorites"] += n
		}
		if k, ok := names[t]; ok {
			out[k] += n
		} else {
			out["other"] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var f int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM vault_folders WHERE user_id = ?`, uid).Scan(&f)
	out["folders"] = f
	return out, nil
}

// ---- two-step login ----

// TwoFactor is one second step (type 0 = authenticator app).
type TwoFactor struct {
	UserID   int64
	Type     int
	Enabled  bool
	Data     string
	LastUsed int64
}

// ListTwoFactor lists a person's second steps.
func (s *Store) ListTwoFactor(ctx context.Context, uid int64) ([]TwoFactor, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT user_id, type, enabled, data, last_used FROM vault_twofactor WHERE user_id = ? ORDER BY type`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TwoFactor{}
	for rows.Next() {
		var t TwoFactor
		var en int
		if err := rows.Scan(&t.UserID, &t.Type, &en, &t.Data, &t.LastUsed); err != nil {
			return nil, err
		}
		t.Enabled = en != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTwoFactor returns one second step.
func (s *Store) GetTwoFactor(ctx context.Context, uid int64, typ int) (*TwoFactor, error) {
	t := &TwoFactor{}
	var en int
	err := s.DB.QueryRowContext(ctx, `SELECT user_id, type, enabled, data, last_used FROM vault_twofactor WHERE user_id = ? AND type = ?`, uid, typ).Scan(&t.UserID, &t.Type, &en, &t.Data, &t.LastUsed)
	if err != nil {
		return nil, notFound(err)
	}
	t.Enabled = en != 0
	return t, nil
}

// SaveTwoFactor inserts or updates a second step.
func (s *Store) SaveTwoFactor(ctx context.Context, t *TwoFactor) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO vault_twofactor (user_id, type, enabled, data, last_used) VALUES (?,?,?,?,?)
		ON CONFLICT(user_id, type) DO UPDATE SET enabled=excluded.enabled, data=excluded.data, last_used=excluded.last_used`,
		t.UserID, t.Type, boolInt(t.Enabled), t.Data, t.LastUsed)
	return err
}

// DeleteTwoFactor removes one second step (typ < 0: all of them).
func (s *Store) DeleteTwoFactor(ctx context.Context, uid int64, typ int) error {
	if typ < 0 {
		_, err := s.DB.ExecContext(ctx, `DELETE FROM vault_twofactor WHERE user_id = ?`, uid)
		return err
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM vault_twofactor WHERE user_id = ? AND type = ?`, uid, typ)
	return err
}

// ---- activity ----

// VaultEvent is one line of a person's vault activity.
type VaultEvent struct {
	ID         int64  `json:"id"`
	Kind       string `json:"kind"`
	DeviceName string `json:"device_name"`
	DeviceType *int   `json:"device_type"`
	IP         string `json:"ip"`
	Detail     string `json:"detail"`
	At         string `json:"at"`
}

// AddVaultEvent records something that happened to a vault; old lines are
// trimmed to the last 500.
func (s *Store) AddVaultEvent(ctx context.Context, uid int64, e VaultEvent) {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO vault_events (user_id, kind, device_name, device_type, ip, detail, at) VALUES (?,?,?,?,?,?,?)`,
		uid, e.Kind, e.DeviceName, intPtr(e.DeviceType), e.IP, e.Detail, Now())
	if err != nil && s.log != nil {
		s.log.Warn("vault event", "err", err)
	}
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM vault_events WHERE user_id = ? AND id NOT IN (SELECT id FROM vault_events WHERE user_id = ? ORDER BY id DESC LIMIT 500)`, uid, uid)
}

// ListVaultEvents returns a person's recent vault activity, newest first.
func (s *Store) ListVaultEvents(ctx context.Context, uid int64, limit int) ([]VaultEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, kind, device_name, device_type, ip, detail, at FROM vault_events WHERE user_id = ? ORDER BY id DESC LIMIT ?`, uid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VaultEvent{}
	for rows.Next() {
		var e VaultEvent
		var dt sql.NullInt64
		if err := rows.Scan(&e.ID, &e.Kind, &e.DeviceName, &dt, &e.IP, &e.Detail, &e.At); err != nil {
			return nil, err
		}
		if dt.Valid {
			v := int(dt.Int64)
			e.DeviceType = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- shared health summary ----

// GetVaultHealth returns the health summary a person shared ("" = none).
func (s *Store) GetVaultHealth(ctx context.Context, uid int64) (string, string, error) {
	var sum, at string
	err := s.DB.QueryRowContext(ctx, `SELECT summary, updated_at FROM vault_health WHERE user_id = ?`, uid).Scan(&sum, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return sum, at, err
}

// SaveVaultHealth stores a person's shared health summary ("" removes it).
func (s *Store) SaveVaultHealth(ctx context.Context, uid int64, summary string) error {
	if summary == "" {
		_, err := s.DB.ExecContext(ctx, `DELETE FROM vault_health WHERE user_id = ?`, uid)
		return err
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO vault_health (user_id, summary, updated_at) VALUES (?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET summary = excluded.summary, updated_at = excluded.updated_at`, uid, summary, Now())
	return err
}

// ---- reminders sent to Pocket Renewals ----

// Reminder is an item's expiry sent to Pocket Renewals.
type Reminder struct {
	CipherUUID string `json:"cipher_id"`
	RenewalID  int64  `json:"renewal_id"`
	Title      string `json:"title"`
	ExpiresOn  string `json:"expires_on"`
	CreatedAt  string `json:"created_at"`
}

// ListReminders lists what a person sent to Pocket Renewals.
func (s *Store) ListReminders(ctx context.Context, uid int64) ([]Reminder, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT cipher_uuid, renewal_id, title, expires_on, created_at FROM vault_reminders WHERE user_id = ? ORDER BY expires_on`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Reminder{}
	for rows.Next() {
		var r Reminder
		if err := rows.Scan(&r.CipherUUID, &r.RenewalID, &r.Title, &r.ExpiresOn, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetReminder returns the reminder sent for an item.
func (s *Store) GetReminder(ctx context.Context, uid int64, cipher string) (*Reminder, error) {
	r := &Reminder{}
	err := s.DB.QueryRowContext(ctx, `SELECT cipher_uuid, renewal_id, title, expires_on, created_at FROM vault_reminders WHERE user_id = ? AND cipher_uuid = ?`, uid, cipher).
		Scan(&r.CipherUUID, &r.RenewalID, &r.Title, &r.ExpiresOn, &r.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return r, nil
}

// SaveReminder records a reminder sent to Pocket Renewals.
func (s *Store) SaveReminder(ctx context.Context, uid int64, r Reminder) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO vault_reminders (user_id, cipher_uuid, renewal_id, title, expires_on, created_at) VALUES (?,?,?,?,?,?)
		ON CONFLICT(user_id, cipher_uuid) DO UPDATE SET renewal_id=excluded.renewal_id, title=excluded.title, expires_on=excluded.expires_on`,
		uid, r.CipherUUID, r.RenewalID, r.Title, r.ExpiresOn, Now())
	return err
}

// DeleteReminder forgets a reminder.
func (s *Store) DeleteReminder(ctx context.Context, uid int64, cipher string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM vault_reminders WHERE user_id = ? AND cipher_uuid = ?`, uid, cipher)
	return err
}
