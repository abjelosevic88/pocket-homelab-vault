package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// ---- the Pocket side of the vault (/api/v1/vault) ----
//
// The web vault in this app is a Bitwarden client like the others: it signs
// in to /identity with the master password and reads /api/sync. These
// routes are the rest, for a person signed in to Pocket Vault: is there a
// vault, make one, what happened to it, the health numbers they chose to
// share, reminders sent to Pocket Renewals, and the Vaultwarden move.

// handleVaultStatus says whether the person has a vault and how to unlock it.
func (s *Server) handleVaultStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := userFrom(ctx)
	out := map[string]any{"has_vault": false, "email": u.Email, "server_url": s.bwBase(r), "live_apps": 0}
	a, err := s.store.GetVaultAccount(ctx, u.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	counts, _ := s.store.VaultCounts(ctx, u.ID)
	devs, _ := s.store.ListDevices(ctx, u.ID)
	tf, _ := s.store.GetTwoFactor(ctx, u.ID, tfAuthenticator)
	last := ""
	if len(devs) > 0 {
		last = store.BWDate(devs[0].UpdatedAt)
	}
	out["has_vault"] = true
	out["email"] = a.Email
	out["name"] = a.Name
	out["kdf"] = map[string]any{"type": a.KdfType, "iterations": a.KdfIterations, "memory": kdfNum(a.KdfMemory), "parallelism": kdfNum(a.KdfParallelism)}
	out["hint"] = a.PasswordHint
	out["counts"] = counts
	out["devices"] = len(devs)
	out["last_used"] = last
	out["two_factor"] = tf != nil && tf.Enabled
	out["created_at"] = store.BWDate(a.CreatedAt)
	out["revision_date"] = a.RevisionDate
	out["live_apps"] = s.bw.hub.countFor(a.UUID)
	pks, _ := s.store.ListPasskeys(ctx, u.ID)
	unlock := 0
	for _, p := range pks {
		if p.Unlocks() {
			unlock++
		}
	}
	out["passkeys"] = len(pks)
	out["passkeys_unlock"] = unlock
	writeJSON(w, http.StatusOK, out)
}

var encString = regexp.MustCompile(`^2\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$`)

// handleVaultSetup creates the signed-in person's vault from what their
// browser made: the master password hash and the keys, already encrypted.
func (s *Server) handleVaultSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := userFrom(ctx)
	if linkApp(ctx) != "" {
		writeErr(w, http.StatusForbidden, "only you can create your vault")
		return
	}
	if _, err := s.store.GetVaultAccount(ctx, u.ID); err == nil {
		writeErr(w, http.StatusConflict, "you already have a vault")
		return
	}
	var in struct {
		MasterPasswordHash string `json:"master_password_hash"`
		Key                string `json:"key"`
		PublicKey          string `json:"public_key"`
		PrivateKey         string `json:"private_key"`
		KdfType            int    `json:"kdf_type"`
		KdfIterations      int    `json:"kdf_iterations"`
		KdfMemory          *int   `json:"kdf_memory"`
		KdfParallelism     *int   `json:"kdf_parallelism"`
		Hint               string `json:"hint"`
		Name               string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.MasterPasswordHash == "" || !encString.MatchString(in.Key) || !encString.MatchString(in.PrivateKey) || in.PublicKey == "" {
		writeErr(w, http.StatusBadRequest, "the browser didn't send a complete set of keys; reload and try again")
		return
	}
	switch in.KdfType {
	case 0:
		if in.KdfIterations < 100000 {
			writeErr(w, http.StatusBadRequest, "PBKDF2 needs at least 100,000 iterations")
			return
		}
		in.KdfMemory, in.KdfParallelism = nil, nil
	case 1:
		if in.KdfIterations < 1 || in.KdfMemory == nil || in.KdfParallelism == nil || *in.KdfMemory < 15 || *in.KdfMemory > 1024 || *in.KdfParallelism < 1 || *in.KdfParallelism > 16 {
			writeErr(w, http.StatusBadRequest, "Argon2id needs at least 1 iteration, 15–1024 MB and 1–16 threads")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "unknown KDF")
		return
	}
	if strings.EqualFold(strings.TrimSpace(in.Hint), "") == false && len(in.Hint) > 200 {
		writeErr(w, http.StatusBadRequest, "the hint is up to 200 characters")
		return
	}
	if _, err := s.store.GetVaultAccountByEmail(ctx, u.Email); err == nil {
		writeErr(w, http.StatusConflict, "a vault with your email already exists")
		return
	}
	salt := bw.RandomBytes(64)
	a := &store.VaultAccount{UserID: u.ID, UUID: uuid.NewString(), Email: u.Email, Name: firstNonEmpty(strings.TrimSpace(in.Name), u.Name),
		MasterSalt: salt, MasterIterations: 600000, MasterHash: bw.HashMaster(in.MasterPasswordHash, salt, 600000), PasswordHint: strings.TrimSpace(in.Hint),
		AKey: in.Key, PrivateKey: in.PrivateKey, PublicKey: in.PublicKey, SecurityStamp: uuid.NewString(), KdfType: in.KdfType, KdfIterations: in.KdfIterations,
		KdfMemory: in.KdfMemory, KdfParallelism: in.KdfParallelism, Enabled: true}
	if len(a.Name) > 50 {
		a.Name = a.Name[:50]
	}
	if err := s.store.CreateVaultAccount(ctx, a); err != nil {
		s.fail(w, err, "create vault")
		return
	}
	s.store.AddVaultEvent(ctx, u.ID, store.VaultEvent{Kind: "created"})
	s.publish(ctx, u.ID, "vault.created", a.UUID, nil)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "email": a.Email})
}

// handleVaultDelete deletes the person's vault (with the master password
// hash, worked out in the browser).
func (s *Server) handleVaultDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := userFrom(ctx)
	if linkApp(ctx) != "" {
		writeErr(w, http.StatusForbidden, "only you can delete your vault")
		return
	}
	var in struct {
		MasterPasswordHash string `json:"master_password_hash"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	a, err := s.store.GetVaultAccount(ctx, u.ID)
	if err != nil {
		s.fail(w, err, "vault")
		return
	}
	if !bw.CheckMaster(in.MasterPasswordHash, a.MasterSalt, a.MasterHash, a.MasterIterations) {
		writeErr(w, http.StatusBadRequest, "that master password isn't right")
		return
	}
	if err := s.store.DeleteVault(ctx, u.ID); err != nil {
		s.fail(w, err, "delete vault")
		return
	}
	s.bwNotifyUser(a, bw.LogOut, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleVaultActivity lists what happened to the vault.
func (s *Server) handleVaultActivity(w http.ResponseWriter, r *http.Request) {
	ev, err := s.store.ListVaultEvents(r.Context(), actorID(r.Context()), queryInt(r, "limit"))
	if err != nil {
		s.fail(w, err, "activity")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// handleVaultDevices lists the signed-in apps (no tokens).
func (s *Server) handleVaultDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.store.ListDevices(r.Context(), actorID(r.Context()))
	if err != nil {
		s.fail(w, err, "devices")
		return
	}
	out := make([]map[string]any, 0, len(devs))
	for _, d := range devs {
		out = append(out, map[string]any{"id": d.UUID, "name": d.Name, "type": d.Type, "type_name": deviceTypeName(d.Type), "kind": deviceKind(d.Type),
			"created_at": store.BWDate(d.CreatedAt), "last_used": store.BWDate(d.UpdatedAt), "ip": d.LastIP, "push": d.PushToken != ""})
	}
	writeJSON(w, http.StatusOK, out)
}

// deviceKind groups device types for icons: phone, extension, desktop, web, cli.
func deviceKind(t int) string {
	switch t {
	case 0, 1, 15:
		return "phone"
	case 2, 3, 4, 5, 19, 20:
		return "extension"
	case 6, 7, 8, 16:
		return "desktop"
	case 23, 24, 25, 21, 22:
		return "cli"
	}
	return "web"
}

func (s *Server) handleVaultRemoveDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uid := actorID(ctx)
	if linkApp(ctx) != "" {
		writeErr(w, http.StatusForbidden, "only you can sign apps out")
		return
	}
	id := strings.ToLower(chiParam(r, "id"))
	d, err := s.store.GetDevice(ctx, uid, id)
	if err != nil {
		s.fail(w, err, "device")
		return
	}
	if err := s.store.DeleteDevice(ctx, uid, id); err != nil {
		s.fail(w, err, "remove device")
		return
	}
	s.store.AddVaultEvent(ctx, uid, store.VaultEvent{Kind: "device_removed", DeviceName: d.Name, DeviceType: &d.Type})
	w.WriteHeader(http.StatusNoContent)
}

// handleVaultSignOutEverywhere ends every app's session at once.
func (s *Server) handleVaultSignOutEverywhere(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if linkApp(ctx) != "" {
		writeErr(w, http.StatusForbidden, "only you can sign apps out")
		return
	}
	a, err := s.store.GetVaultAccount(ctx, actorID(ctx))
	if err != nil {
		s.fail(w, err, "vault")
		return
	}
	if err := s.signOutEverywhere(ctx, a); err != nil {
		s.fail(w, err, "sign out")
		return
	}
	s.store.AddVaultEvent(ctx, a.UserID, store.VaultEvent{Kind: "signed_out_everywhere"})
	s.bwNotifyUser(a, bw.LogOut, nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- health numbers shared with other Pocket apps ----

// healthKeys are the only numbers a summary may hold.
var healthKeys = map[string]bool{"logins": true, "weak": true, "reused": true, "old": true, "breached": true, "no_password": true, "http": true,
	"with_totp": true, "score": true, "checked_breaches": true}

func (s *Server) handlePutVaultHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uid := actorID(ctx)
	if linkApp(ctx) != "" {
		writeErr(w, http.StatusForbidden, "only your own browser can share these numbers")
		return
	}
	st, _ := s.store.GetSettings(ctx, uid)
	var in map[string]any
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !st.ShareHealth {
		_ = s.store.SaveVaultHealth(ctx, uid, "")
		writeJSON(w, http.StatusOK, map[string]any{"shared": false})
		return
	}
	clean := map[string]any{}
	for k, v := range in {
		if !healthKeys[k] {
			continue
		}
		switch n := v.(type) {
		case float64:
			if n >= 0 && n < 1e6 {
				clean[k] = int(n)
			}
		case bool:
			clean[k] = n
		}
	}
	b, _ := json.Marshal(clean)
	if err := s.store.SaveVaultHealth(ctx, uid, string(b)); err != nil {
		s.fail(w, err, "save health")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shared": true})
}

// handleVaultOverview is what other Pocket apps (vault:read) and Pocket AI
// may know: counts, apps signed in, two-step login, and the health numbers
// the person chose to share. Never a name, a username or a password.
func (s *Server) handleVaultOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uid := actorID(ctx)
	out := map[string]any{"has_vault": false, "url": s.cfg.BaseURL}
	a, err := s.store.GetVaultAccount(ctx, uid)
	if err != nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	counts, _ := s.store.VaultCounts(ctx, uid)
	devs, _ := s.store.ListDevices(ctx, uid)
	tf, _ := s.store.GetTwoFactor(ctx, uid, tfAuthenticator)
	apps := []map[string]any{}
	for _, d := range devs {
		apps = append(apps, map[string]any{"app": deviceTypeName(d.Type), "kind": deviceKind(d.Type), "last_used": store.BWDate(d.UpdatedAt)})
	}
	out["has_vault"] = true
	out["items"] = counts
	out["apps"] = apps
	out["two_factor"] = tf != nil && tf.Enabled
	out["kdf"] = map[int]string{0: "PBKDF2", 1: "Argon2id"}[a.KdfType]
	out["kdf_iterations"] = a.KdfIterations
	out["last_change"] = a.RevisionDate
	if sum, at, _ := s.store.GetVaultHealth(ctx, uid); sum != "" {
		var h map[string]any
		_ = json.Unmarshal([]byte(sum), &h)
		out["health"] = h
		out["health_at"] = at
	}
	if ev, err := s.store.ListVaultEvents(ctx, uid, 20); err == nil {
		recent := []map[string]any{}
		for _, e := range ev {
			recent = append(recent, map[string]any{"kind": e.Kind, "app": e.DeviceName, "at": e.At})
		}
		out["recent"] = recent
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- reminders in Pocket Renewals ----

func (s *Server) handleListReminders(w http.ResponseWriter, r *http.Request) {
	rs, err := s.store.ListReminders(r.Context(), actorID(r.Context()))
	if err != nil {
		s.fail(w, err, "reminders")
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

var ymd = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// handleCreateReminder sends one expiry date (a card, a passport) to Pocket
// Renewals. The browser decrypted the item and sends only what the person
// saw in the form: a title, who it's for, the date and the last digits.
func (s *Server) handleCreateReminder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uid := actorID(ctx)
	var in struct {
		CipherID  string `json:"cipher_id"`
		Title     string `json:"title"`
		Kind      string `json:"kind"`
		Holder    string `json:"holder"`
		Number    string `json:"number"`
		ExpiresOn string `json:"expires_on"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	in.CipherID = strings.ToLower(strings.TrimSpace(in.CipherID))
	if _, err := s.store.GetCipher(ctx, uid, in.CipherID); err != nil {
		s.fail(w, err, "item")
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" || len(in.Title) > 120 || !ymd.MatchString(in.ExpiresOn) {
		writeErr(w, http.StatusBadRequest, "a title and an expiry date (YYYY-MM-DD) are needed")
		return
	}
	if _, err := time.Parse("2006-01-02", in.ExpiresOn); err != nil {
		writeErr(w, http.StatusBadRequest, "that expiry date doesn't exist")
		return
	}
	switch in.Kind {
	case "passport", "id_card", "driving_licence", "visa", "licence", "other":
	default:
		in.Kind = "other"
	}
	if len(in.Number) > 8 {
		in.Number = "•••• " + in.Number[len(in.Number)-4:]
	}
	c := s.clients(ctx, uid)
	conn, err := c.conn(ctx, appRenewals, scopeRenewalsWrite)
	if err != nil {
		if isNotConnected(err) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	body := map[string]any{"title": in.Title, "kind": in.Kind, "holder": in.Holder, "number": in.Number, "expires_on": in.ExpiresOn,
		"external_id": in.CipherID, "source_url": s.cfg.BaseURL + "/item/" + in.CipherID,
		"notes": "Added from Pocket Vault. The details stay in your vault."}
	var res struct {
		ID int64 `json:"id"`
	}
	if err := conn.client.Do(ctx, http.MethodPost, "/api/v1/renewals", body, &res); err != nil {
		writeErr(w, http.StatusBadGateway, "Pocket Renewals: "+err.Error())
		return
	}
	rem := store.Reminder{CipherUUID: in.CipherID, RenewalID: res.ID, Title: in.Title, ExpiresOn: in.ExpiresOn}
	if err := s.store.SaveReminder(ctx, uid, rem); err != nil {
		s.fail(w, err, "save reminder")
		return
	}
	open := ""
	if conn.public != "" && res.ID > 0 {
		open = strings.TrimRight(conn.public, "/") + fmt.Sprintf("/renewals/%d", res.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "renewal_id": res.ID, "open_url": open})
}

func (s *Server) handleDeleteReminder(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteReminder(r.Context(), actorID(r.Context()), strings.ToLower(chiParam(r, "id"))); err != nil {
		s.fail(w, err, "reminder")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- moving from Vaultwarden (admin) ----

// handleImportVaultwarden takes Vaultwarden's db.sqlite3 (and, to keep the
// apps signed in, its rsa_key.pem) as an upload.
func (s *Server) handleImportVaultwarden(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "upload Vaultwarden's db.sqlite3 (the form was not readable: "+err.Error()+")")
		return
	}
	defer r.MultipartForm.RemoveAll()
	tmp, err := os.MkdirTemp(s.cfg.DataDir, "vw-upload-")
	if err != nil {
		s.fail(w, err, "upload")
		return
	}
	defer os.RemoveAll(tmp)
	save := func(field, name string) (string, error) {
		f, _, err := r.FormFile(field)
		if err != nil {
			return "", nil
		}
		defer f.Close()
		p := filepath.Join(tmp, name)
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, f); err != nil {
			out.Close()
			return "", err
		}
		return p, out.Close()
	}
	db, err := save("db", "db.sqlite3")
	if err != nil || db == "" {
		writeErr(w, http.StatusBadRequest, "choose Vaultwarden's db.sqlite3")
		return
	}
	if _, err := save("wal", "db.sqlite3-wal"); err != nil {
		s.fail(w, err, "upload")
		return
	}
	var keyPEM []byte
	if f, _, err := r.FormFile("key"); err == nil {
		keyPEM, _ = io.ReadAll(io.LimitReader(f, 64<<10))
		f.Close()
	}
	rep, err := s.ImportVaultwarden(r.Context(), db, VWOptions{Replace: r.FormValue("replace") == "true", KeyPEM: keyPEM})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("vaultwarden import", "by", userFrom(r.Context()).Email, "accounts", len(rep.Accounts), "key_kept", rep.KeyKept)
	writeJSON(w, http.StatusOK, rep)
}
