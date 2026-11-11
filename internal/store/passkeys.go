package store

import "context"

// Passkey is one passkey that signs in to a vault (and, with keys, unlocks it).
type Passkey struct {
	UserID              int64
	UUID                string
	Name                string
	CredentialID        string // base64url
	Credential          string // JSON (webauthn.Credential)
	SupportsPRF         bool
	EncryptedUserKey    string
	EncryptedPublicKey  string
	EncryptedPrivateKey string
	LastUsedAt          *string
	CreatedAt           string
}

// Unlocks says whether this passkey carries the keys that open the vault.
func (p *Passkey) Unlocks() bool {
	return p.EncryptedUserKey != "" && p.EncryptedPrivateKey != ""
}

const passkeyCols = `user_id, uuid, name, credential_id, credential, supports_prf, encrypted_user_key, encrypted_public_key, encrypted_private_key, last_used_at, created_at`

type scanner interface{ Scan(dest ...any) error }

func scanPasskey(row scanner) (*Passkey, error) {
	p := &Passkey{}
	var prf int
	if err := row.Scan(&p.UserID, &p.UUID, &p.Name, &p.CredentialID, &p.Credential, &prf, &p.EncryptedUserKey, &p.EncryptedPublicKey, &p.EncryptedPrivateKey, &p.LastUsedAt, &p.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	p.SupportsPRF = prf != 0
	return p, nil
}

// ListPasskeys lists a person's passkeys, oldest first.
func (s *Store) ListPasskeys(ctx context.Context, uid int64) ([]Passkey, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+passkeyCols+` FROM vault_passkeys WHERE user_id = ? ORDER BY created_at, uuid`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Passkey{}
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetPasskey returns one of a person's passkeys by its uuid.
func (s *Store) GetPasskey(ctx context.Context, uid int64, id string) (*Passkey, error) {
	return scanPasskey(s.DB.QueryRowContext(ctx, `SELECT `+passkeyCols+` FROM vault_passkeys WHERE user_id = ? AND uuid = ?`, uid, id))
}

// GetPasskeyByCredential finds a passkey by the id the authenticator gave it.
func (s *Store) GetPasskeyByCredential(ctx context.Context, credID string) (*Passkey, error) {
	return scanPasskey(s.DB.QueryRowContext(ctx, `SELECT `+passkeyCols+` FROM vault_passkeys WHERE credential_id = ?`, credID))
}

// AddPasskey stores a new passkey.
func (s *Store) AddPasskey(ctx context.Context, p *Passkey) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO vault_passkeys (user_id, uuid, name, credential_id, credential, supports_prf, encrypted_user_key, encrypted_public_key, encrypted_private_key)
		VALUES (?,?,?,?,?,?,?,?,?)`, p.UserID, p.UUID, p.Name, p.CredentialID, p.Credential, boolInt(p.SupportsPRF), p.EncryptedUserKey, p.EncryptedPublicKey, p.EncryptedPrivateKey)
	return err
}

// SavePasskey updates the parts that change after it is made: the
// credential (sign count), the keys and when it was last used.
func (s *Store) SavePasskey(ctx context.Context, p *Passkey) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE vault_passkeys SET name=?, credential=?, supports_prf=?, encrypted_user_key=?, encrypted_public_key=?, encrypted_private_key=?, last_used_at=?
		WHERE user_id = ? AND uuid = ?`, p.Name, p.Credential, boolInt(p.SupportsPRF), p.EncryptedUserKey, p.EncryptedPublicKey, p.EncryptedPrivateKey, strPtr(p.LastUsedAt), p.UserID, p.UUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey removes one passkey.
func (s *Store) DeletePasskey(ctx context.Context, uid int64, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM vault_passkeys WHERE user_id = ? AND uuid = ?`, uid, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AnyPasskeys says whether anyone here signs in with a passkey (the sign-in
// page offers the button then).
func (s *Store) AnyPasskeys(ctx context.Context) bool {
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM vault_passkeys`).Scan(&n)
	return n > 0
}
