package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// ---- moving from Vaultwarden ----
//
// Vaultwarden keeps the same encrypted data the apps made, so a move is a
// copy: accounts (master password check and keys), folders, items,
// favourites, archive, the bin, signed-in apps and the authenticator-app
// second step. Nothing is decrypted or re-encrypted. With Vaultwarden's
// rsa_key.pem as well, the apps that were signed in stay signed in (their
// tokens keep working) once the address points here.

// VWReport says what one import did.
type VWReport struct {
	Accounts []VWAccountReport `json:"accounts"`
	KeyKept  bool              `json:"key_kept"`
	Notes    []string          `json:"notes"`
}

// VWAccountReport is one account's part of an import.
type VWAccountReport struct {
	Email     string `json:"email"`
	Status    string `json:"status"` // imported | replaced | skipped
	Reason    string `json:"reason,omitempty"`
	Items     int    `json:"items"`
	Folders   int    `json:"folders"`
	Devices   int    `json:"devices"`
	TwoFactor bool   `json:"two_factor"`
}

// VWOptions steer an import.
type VWOptions struct {
	Replace bool   // replace a vault that already exists here
	Only    string // import just this email
	KeyPEM  []byte // Vaultwarden's rsa_key.pem (keeps apps signed in)
}

// ImportVaultwarden copies a Vaultwarden database (db.sqlite3, with its -wal
// next to it when Vaultwarden was running) into this server. It reads a
// private copy, never the file itself.
func (s *Server) ImportVaultwarden(ctx context.Context, dbPath string, opt VWOptions) (*VWReport, error) {
	tmp, err := os.MkdirTemp(s.cfg.DataDir, "vw-import-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	cp := filepath.Join(tmp, "db.sqlite3")
	if err := copyFile(dbPath, cp); err != nil {
		return nil, fmt.Errorf("read the Vaultwarden database: %w", err)
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbPath + sfx); err == nil {
			if err := copyFile(dbPath+sfx, cp+sfx); err != nil {
				return nil, err
			}
		}
	}
	vw, err := sql.Open("sqlite", "file:"+cp+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer vw.Close()
	vw.SetMaxOpenConns(1)
	var n int
	if err := vw.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&n); err != nil {
		return nil, errors.New("this is not a Vaultwarden database (no users table)")
	}
	rep := &VWReport{Accounts: []VWAccountReport{}, Notes: []string{}}
	if len(opt.KeyPEM) > 0 {
		k, err := bw.ParseKey(opt.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("rsa_key.pem: %w", err)
		}
		if err := os.WriteFile(s.cfg.DataDir+"/rsa_key.pem", opt.KeyPEM, 0o600); err != nil {
			return nil, err
		}
		s.setBWKey(k)
		rep.KeyKept = true
	}

	type vwUser struct {
		uuid, email, name, hint, akey, priv, pub, stamp, stampEx, recover, eq, ex, apiKey, created, updated string
		hash, salt                                                                                          []byte
		iter, kdf, kdfIter, enabled                                                                         int
		mem, par                                                                                            sql.NullInt64
		avatar                                                                                              sql.NullString
	}
	rows, err := vw.QueryContext(ctx, `SELECT uuid, email, name, COALESCE(password_hint,''), akey, COALESCE(private_key,''), COALESCE(public_key,''),
		security_stamp, COALESCE(stamp_exception,''), COALESCE(totp_recover,''), equivalent_domains, excluded_globals, COALESCE(api_key,''),
		created_at, updated_at, password_hash, salt, password_iterations, client_kdf_type, client_kdf_iter, enabled, client_kdf_memory, client_kdf_parallelism, avatar_color
		FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	var users []vwUser
	for rows.Next() {
		var u vwUser
		if err := rows.Scan(&u.uuid, &u.email, &u.name, &u.hint, &u.akey, &u.priv, &u.pub, &u.stamp, &u.stampEx, &u.recover, &u.eq, &u.ex, &u.apiKey,
			&u.created, &u.updated, &u.hash, &u.salt, &u.iter, &u.kdf, &u.kdfIter, &u.enabled, &u.mem, &u.par, &u.avatar); err != nil {
			rows.Close()
			return nil, err
		}
		users = append(users, u)
	}
	rows.Close()

	for _, u := range users {
		email := strings.ToLower(strings.TrimSpace(u.email))
		r := VWAccountReport{Email: email}
		if opt.Only != "" && !strings.EqualFold(opt.Only, email) {
			continue
		}
		if u.akey == "" || len(u.hash) == 0 {
			r.Status, r.Reason = "skipped", "the account was never finished (no master password)"
			rep.Accounts = append(rep.Accounts, r)
			continue
		}
		pu, err := s.store.GetUserByEmail(ctx, email)
		if err != nil {
			if pu, err = s.firstOrSystemUser(ctx, email, u.name); err != nil {
				return nil, err
			}
		}
		if _, err := s.store.GetVaultAccount(ctx, pu.ID); err == nil {
			if !opt.Replace {
				r.Status, r.Reason = "skipped", "this person already has a vault here (import again with “replace”)"
				rep.Accounts = append(rep.Accounts, r)
				continue
			}
			if err := s.store.DeleteVault(ctx, pu.ID); err != nil {
				return nil, err
			}
			r.Status = "replaced"
		} else {
			r.Status = "imported"
		}
		if other, err := s.store.GetVaultAccountByUUID(ctx, u.uuid); err == nil && other.UserID != pu.ID {
			r.Status, r.Reason = "skipped", "another person here already holds this vault"
			rep.Accounts = append(rep.Accounts, r)
			continue
		}
		a := &store.VaultAccount{UserID: pu.ID, UUID: strings.ToLower(u.uuid), Email: email, Name: u.name, MasterHash: u.hash, MasterSalt: u.salt,
			MasterIterations: u.iter, PasswordHint: u.hint, AKey: u.akey, PrivateKey: u.priv, PublicKey: u.pub, SecurityStamp: u.stamp,
			StampException: u.stampEx, KdfType: u.kdf, KdfIterations: u.kdfIter, TotpRecover: u.recover, EquivalentDomains: u.eq, ExcludedGlobals: u.ex,
			APIKey: u.apiKey, Enabled: u.enabled != 0, RevisionDate: store.BWDate(u.updated), CreatedAt: store.BWDate(u.created)}
		if u.mem.Valid {
			v := int(u.mem.Int64)
			a.KdfMemory = &v
		}
		if u.par.Valid {
			v := int(u.par.Int64)
			a.KdfParallelism = &v
		}
		if u.avatar.Valid {
			a.AvatarColor = &u.avatar.String
		}
		if err := s.store.CreateVaultAccount(ctx, a); err != nil {
			return nil, fmt.Errorf("%s: %w", email, err)
		}
		uid := pu.ID

		// folders
		frows, err := vw.QueryContext(ctx, `SELECT uuid, name, created_at, updated_at FROM folders WHERE user_uuid = ?`, u.uuid)
		if err != nil {
			return nil, err
		}
		var folders []store.Folder
		for frows.Next() {
			f := store.Folder{UserID: uid}
			if err := frows.Scan(&f.UUID, &f.Name, &f.CreatedAt, &f.UpdatedAt); err != nil {
				frows.Close()
				return nil, err
			}
			folders = append(folders, f)
		}
		frows.Close()
		for _, f := range folders {
			f.UUID = strings.ToLower(f.UUID)
			f.CreatedAt = store.BWDate(f.CreatedAt)
			if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO vault_folders (user_id, uuid, name, created_at, updated_at) VALUES (?,?,?,?,?)`,
				uid, f.UUID, f.Name, f.CreatedAt, store.BWDate(f.UpdatedAt)); err != nil {
				return nil, fmt.Errorf("%s folders: %w", email, err)
			}
			r.Folders++
		}

		// items
		crows, err := vw.QueryContext(ctx, `SELECT c.uuid, c.atype, c.name, c.notes, c.fields, c.data, c.password_history, c.deleted_at, COALESCE(c.reprompt,0), c.key,
			c.created_at, c.updated_at,
			(SELECT fc.folder_uuid FROM folders_ciphers fc JOIN folders f ON f.uuid = fc.folder_uuid WHERE fc.cipher_uuid = c.uuid AND f.user_uuid = ? LIMIT 1),
			EXISTS(SELECT 1 FROM favorites fv WHERE fv.cipher_uuid = c.uuid AND fv.user_uuid = ?),
			(SELECT ar.archived_at FROM archives ar WHERE ar.cipher_uuid = c.uuid AND ar.user_uuid = ?)
			FROM ciphers c WHERE c.user_uuid = ? AND c.organization_uuid IS NULL`, u.uuid, u.uuid, u.uuid, u.uuid)
		if err != nil {
			// older Vaultwarden without the archives table
			crows, err = vw.QueryContext(ctx, `SELECT c.uuid, c.atype, c.name, c.notes, c.fields, c.data, c.password_history, c.deleted_at, COALESCE(c.reprompt,0), c.key,
				c.created_at, c.updated_at,
				(SELECT fc.folder_uuid FROM folders_ciphers fc JOIN folders f ON f.uuid = fc.folder_uuid WHERE fc.cipher_uuid = c.uuid AND f.user_uuid = ? LIMIT 1),
				EXISTS(SELECT 1 FROM favorites fv WHERE fv.cipher_uuid = c.uuid AND fv.user_uuid = ?), NULL
				FROM ciphers c WHERE c.user_uuid = ? AND c.organization_uuid IS NULL`, u.uuid, u.uuid, u.uuid)
			if err != nil {
				return nil, err
			}
		}
		var items []store.Cipher
		for crows.Next() {
			c := store.Cipher{UserID: uid}
			var notes, fields, hist, deleted, key, folder, archived sql.NullString
			var fav int
			if err := crows.Scan(&c.UUID, &c.Type, &c.Name, &notes, &fields, &c.Data, &hist, &deleted, &c.Reprompt, &key, &c.CreatedAt, &c.UpdatedAt, &folder, &fav, &archived); err != nil {
				crows.Close()
				return nil, err
			}
			ns := func(v sql.NullString, date bool) *string {
				if !v.Valid {
					return nil
				}
				s := v.String
				if date {
					s = store.BWDate(s)
				}
				return &s
			}
			c.Notes, c.Fields, c.PasswordHistory, c.Key = ns(notes, false), ns(fields, false), ns(hist, false), ns(key, false)
			c.DeletedAt, c.ArchivedAt = ns(deleted, true), ns(archived, true)
			if folder.Valid {
				f := strings.ToLower(folder.String)
				c.FolderUUID = &f
			}
			c.Favorite = fav != 0
			c.CreatedAt, c.UpdatedAt = store.BWDate(c.CreatedAt), store.BWDate(c.UpdatedAt)
			items = append(items, c)
		}
		crows.Close()
		for i := range items {
			if err := s.store.SaveCipher(ctx, &items[i], true); err != nil {
				return nil, fmt.Errorf("%s items: %w", email, err)
			}
			r.Items++
		}

		// signed-in apps
		drows, err := vw.QueryContext(ctx, `SELECT uuid, name, atype, COALESCE(push_token,''), COALESCE(push_uuid,''), refresh_token, COALESCE(twofactor_remember,''), created_at, updated_at
			FROM devices WHERE user_uuid = ?`, u.uuid)
		if err != nil {
			return nil, err
		}
		var devs []store.Device
		for drows.Next() {
			d := store.Device{UserID: uid}
			if err := drows.Scan(&d.UUID, &d.Name, &d.Type, &d.PushToken, &d.PushUUID, &d.RefreshToken, &d.TwoFactorRemember, &d.CreatedAt, &d.UpdatedAt); err != nil {
				drows.Close()
				return nil, err
			}
			devs = append(devs, d)
		}
		drows.Close()
		for _, d := range devs {
			d.UUID = strings.ToLower(d.UUID)
			d.CreatedAt, d.UpdatedAt = store.BWDate(d.CreatedAt), store.BWDate(d.UpdatedAt)
			if err := s.store.SaveDevice(ctx, &d, false); err != nil {
				return nil, fmt.Errorf("%s devices: %w", email, err)
			}
			r.Devices++
		}

		// the authenticator app (other second steps don't exist here)
		trows, err := vw.QueryContext(ctx, `SELECT atype, enabled, data, last_used FROM twofactor WHERE user_uuid = ?`, u.uuid)
		if err != nil {
			return nil, err
		}
		var tfs []store.TwoFactor
		others := 0
		for trows.Next() {
			t := store.TwoFactor{UserID: uid}
			var en int
			if err := trows.Scan(&t.Type, &en, &t.Data, &t.LastUsed); err != nil {
				trows.Close()
				return nil, err
			}
			t.Enabled = en != 0
			if t.Type == tfAuthenticator {
				tfs = append(tfs, t)
			} else if t.Type != tfRemember && t.Type < 1000 {
				others++
			}
		}
		trows.Close()
		for i := range tfs {
			if err := s.store.SaveTwoFactor(ctx, &tfs[i]); err != nil {
				return nil, err
			}
			r.TwoFactor = r.TwoFactor || tfs[i].Enabled
		}
		if others > 0 {
			rep.Notes = append(rep.Notes, email+": a second step other than an authenticator app (email, security key…) was left out — set up an authenticator app under Security.")
		}
		if n := countVW(ctx, vw, `SELECT COUNT(1) FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid WHERE c.user_uuid = ?`, u.uuid); n > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %d attachment(s) stay in Vaultwarden (attachments aren't available here yet).", email, n))
		}
		if n := countVW(ctx, vw, `SELECT COUNT(1) FROM sends WHERE user_uuid = ?`, u.uuid); n > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %d Send(s) were left out.", email, n))
		}
		if n := countVW(ctx, vw, `SELECT COUNT(1) FROM users_organizations WHERE user_uuid = ?`, u.uuid); n > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: belongs to %d organisation(s); shared items stay in Vaultwarden.", email, n))
		}
		s.store.AddVaultEvent(ctx, uid, store.VaultEvent{Kind: "imported", Detail: fmt.Sprintf("from Vaultwarden: %d items, %d folders, %d apps", r.Items, r.Folders, r.Devices)})
		rep.Accounts = append(rep.Accounts, r)
	}
	if !rep.KeyKept {
		rep.Notes = append(rep.Notes, "Without Vaultwarden's rsa_key.pem the apps sign in again once (same email and master password).")
	}
	return rep, nil
}

func countVW(ctx context.Context, db *sql.DB, q string, args ...any) int {
	var n int
	_ = db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
