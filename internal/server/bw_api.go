package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

func chiParam(r *http.Request, name string) string { return chi.URLParam(r, name) }

// bwRoutes mounts the API the Bitwarden apps call under /api.
func (s *Server) bwRoutes(r chi.Router) {
	r.Get("/config", s.handleBWConfig)
	r.Get("/alive", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, store.BWNow()) })
	r.Get("/now", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, store.BWNow()) })
	r.Get("/version", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, bwServerVersion) })
	r.Post("/accounts/prelogin", s.handlePrelogin)
	r.Post("/accounts/register", s.handleRegister)
	r.Post("/accounts/password-hint", func(w http.ResponseWriter, r *http.Request) {
		bwErr(w, http.StatusBadRequest, "This server doesn't send email. Your hint is shown in Pocket Vault under Security.")
	})
	r.Get("/devices/knowndevice", s.handleKnownDevice)
	r.Get("/devices/knowndevice/{email}/{uuid}", s.handleKnownDevice)

	r.Group(func(r chi.Router) {
		r.Use(s.bwAuth)
		r.Get("/sync", s.handleSync)

		r.Get("/accounts/profile", s.handleBWProfile)
		r.Put("/accounts/profile", s.handleBWPutProfile)
		r.Post("/accounts/profile", s.handleBWPutProfile)
		r.Put("/accounts/avatar", s.handleBWAvatar)
		r.Get("/accounts/revision-date", s.handleRevisionDate)
		r.Post("/accounts/keys", s.handleBWKeys)
		r.Post("/accounts/password", s.handleBWPassword)
		r.Post("/accounts/kdf", s.handleBWKdf)
		r.Post("/accounts/security-stamp", s.handleBWSecurityStamp)
		r.Post("/accounts/verify-password", s.handleBWVerifyPassword)
		r.Post("/accounts/verify-email", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		r.Post("/accounts/delete", s.handleBWDeleteAccount)
		r.Delete("/accounts", s.handleBWDeleteAccount)
		r.Post("/accounts/key-management/user-key-id", s.handleBWUserKeyID)
		r.Post("/accounts/key-management/rotate-user-account-keys", notYet("Rotating your encryption key isn't available yet. Changing the master password works."))
		r.Post("/accounts/email-token", notYet("Your email is your login and the salt of your key here; it can't be changed."))
		r.Post("/accounts/email", notYet("Your email is your login and the salt of your key here; it can't be changed."))
		r.Post("/accounts/api-key", notYet("Personal API keys aren't available; sign in with your master password."))
		r.Post("/accounts/rotate-api-key", notYet("Personal API keys aren't available; sign in with your master password."))
		r.Get("/users/{id}/public-key", s.handleBWPublicKey)

		r.Get("/devices", s.handleBWDevices)
		r.Get("/devices/identifier/{id}", s.handleBWDevice)
		r.Post("/devices/identifier/{id}/token", s.handleBWPushToken)
		r.Put("/devices/identifier/{id}/token", s.handleBWPushToken)
		r.Put("/devices/identifier/{id}/clear-token", s.handleBWClearPushToken)
		r.Post("/devices/identifier/{id}/clear-token", s.handleBWClearPushToken)
		r.Put("/devices/identifier/{id}/web-push-auth", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		r.Post("/devices/{id}/deactivate", s.handleBWRemoveDevice)
		r.Delete("/devices/{id}", s.handleBWRemoveDevice)

		r.Get("/ciphers", s.handleBWCiphers)
		r.Post("/ciphers", s.handleBWCreateCipher)
		r.Post("/ciphers/create", s.handleBWCreateCipher)
		r.Post("/ciphers/admin", s.handleBWCreateCipher)
		r.Post("/ciphers/import", s.handleBWImport)
		r.Post("/ciphers/purge", s.handleBWPurge)
		r.Delete("/ciphers", s.handleBWDeleteMany(false))
		r.Post("/ciphers/delete", s.handleBWDeleteMany(false))
		r.Put("/ciphers/delete", s.handleBWDeleteMany(true))
		r.Delete("/ciphers/admin", s.handleBWDeleteMany(false))
		r.Post("/ciphers/delete-admin", s.handleBWDeleteMany(false))
		r.Put("/ciphers/delete-admin", s.handleBWDeleteMany(true))
		r.Put("/ciphers/restore", s.handleBWRestoreMany)
		r.Put("/ciphers/restore-admin", s.handleBWRestoreMany)
		r.Post("/ciphers/move", s.handleBWMove)
		r.Put("/ciphers/move", s.handleBWMove)
		r.Put("/ciphers/archive", s.handleBWArchiveMany(true))
		r.Put("/ciphers/unarchive", s.handleBWArchiveMany(false))
		r.Post("/ciphers/share", notYet(noSharing))
		r.Put("/ciphers/share", notYet(noSharing))
		r.Post("/ciphers/bulk-collections", notYet(noSharing))
		r.Get("/ciphers/organization-details", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, bwList([]any{})) })
		r.Route("/ciphers/{id}", func(r chi.Router) {
			r.Get("/", s.handleBWCipher)
			r.Get("/details", s.handleBWCipher)
			r.Get("/admin", s.handleBWCipher)
			r.Put("/", s.handleBWUpdateCipher)
			r.Post("/", s.handleBWUpdateCipher)
			r.Put("/admin", s.handleBWUpdateCipher)
			r.Post("/admin", s.handleBWUpdateCipher)
			r.Put("/partial", s.handleBWPartial)
			r.Post("/partial", s.handleBWPartial)
			r.Delete("/", s.handleBWDeleteCipher(false))
			r.Post("/delete", s.handleBWDeleteCipher(false))
			r.Delete("/admin", s.handleBWDeleteCipher(false))
			r.Post("/delete-admin", s.handleBWDeleteCipher(false))
			r.Put("/delete", s.handleBWDeleteCipher(true))
			r.Put("/delete-admin", s.handleBWDeleteCipher(true))
			r.Put("/restore", s.handleBWRestore)
			r.Put("/restore-admin", s.handleBWRestore)
			r.Put("/archive", s.handleBWArchive(true))
			r.Put("/unarchive", s.handleBWArchive(false))
			r.Post("/share", notYet(noSharing))
			r.Put("/share", notYet(noSharing))
			r.Put("/collections", notYet(noSharing))
			r.Post("/collections", notYet(noSharing))
			r.Put("/collections_v2", notYet(noSharing))
			r.Post("/collections_v2", notYet(noSharing))
			r.Post("/attachment/v2", notYet(noAttachments))
			r.Post("/attachment", notYet(noAttachments))
			r.Get("/events", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, bwList([]any{})) })
		})

		r.Get("/folders", s.handleBWFolders)
		r.Post("/folders", s.handleBWSaveFolder)
		r.Get("/folders/{id}", s.handleBWFolder)
		r.Put("/folders/{id}", s.handleBWSaveFolder)
		r.Post("/folders/{id}", s.handleBWSaveFolder)
		r.Delete("/folders/{id}", s.handleBWDeleteFolder)
		r.Post("/folders/{id}/delete", s.handleBWDeleteFolder)

		r.Get("/two-factor", s.handleBWTwoFactor)
		r.Post("/two-factor/get-authenticator", s.handleBWGetAuthenticator)
		r.Post("/two-factor/authenticator", s.handleBWEnableAuthenticator)
		r.Put("/two-factor/authenticator", s.handleBWEnableAuthenticator)
		r.Delete("/two-factor/authenticator", s.handleBWDisableTwoFactor)
		r.Post("/two-factor/disable", s.handleBWDisableTwoFactor)
		r.Put("/two-factor/disable", s.handleBWDisableTwoFactor)
		r.Post("/two-factor/get-recover", s.handleBWGetRecover)
		r.Get("/two-factor/get-device-verification-settings", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"isDeviceVerificationSectionEnabled": false, "unknownDeviceVerificationEnabled": false, "object": "deviceVerificationSettings"})
		})
		for _, p := range []string{"/two-factor/get-email", "/two-factor/send-email", "/two-factor/email", "/two-factor/get-webauthn", "/two-factor/get-webauthn-challenge",
			"/two-factor/webauthn", "/two-factor/get-yubikey", "/two-factor/yubikey", "/two-factor/get-duo", "/two-factor/duo"} {
			r.Post(p, notYet("Only an authenticator app is available for two-step login here."))
			r.Put(p, notYet("Only an authenticator app is available for two-step login here."))
		}

		r.Get("/settings/domains", s.handleBWDomains)
		r.Post("/settings/domains", s.handleBWPutDomains)
		r.Put("/settings/domains", s.handleBWPutDomains)

		// Features this server doesn't have yet answer as empty lists, so
		// the apps show nothing instead of an error.
		empty := func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, bwList([]any{})) }
		for _, p := range []string{"/collections", "/sends", "/emergency-access/trusted", "/emergency-access/granted", "/auth-requests", "/auth-requests/pending",
			"/tasks", "/notifications", "/webauthn", "/organizations", "/policies", "/providers"} {
			r.Get(p, empty)
		}
		for _, p := range []string{"/sends", "/sends/file/v2", "/sends/file"} {
			r.Post(p, notYet("Send isn't available yet."))
		}
		r.Post("/emergency-access/invite", notYet("Emergency access isn't available yet."))
		r.Post("/organizations", notYet(noSharing))
		r.Post("/auth-requests", notYet("Signing in with another device isn't available; use your master password."))
		r.Get("/plans", empty)
		r.Get("/hibp/breach", func(w http.ResponseWriter, r *http.Request) {
			bwErr(w, http.StatusNotFound, "Breach reports aren't available here; Pocket Vault's Health page checks passwords privately.")
		})
	})
}

const (
	noSharing     = "Sharing and organisations aren't available yet."
	noAttachments = "Attachments aren't available yet."
)

func notYet(msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { bwErr(w, http.StatusBadRequest, msg) }
}

// bwServerVersion is the Bitwarden server version this server answers as.
// The apps turn features on by it (per-item keys from 2024.2.0, unlock data
// on the phones from 2025.8.0), so it follows what Vaultwarden reports.
const bwServerVersion = "2026.6.0"

func (s *Server) handleBWConfig(w http.ResponseWriter, r *http.Request) {
	base := s.bwBase(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"version": bwServerVersion, "gitHash": nil,
		"server":   map[string]any{"name": "Pocket Vault", "url": "https://github.com/abjelosevic88/pocket-homelab-vault"},
		"settings": map[string]any{"disableUserRegistration": true, "suppressOnboardingInterstitials": true},
		"environment": map[string]any{"vault": base, "api": base + "/api", "identity": base + "/identity", "notifications": base + "/notifications",
			"sso": "", "cloudRegion": nil},
		"push":          map[string]any{"pushTechnology": 0, "vapidPublicKey": nil},
		"featureStates": map[string]any{"pm-19148-innovation-archive": true},
		"communication": nil,
		"object":        "config",
	})
}

// ---- account ----

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b := bwFrom(ctx)
	a := b.acct
	ciphers, err := s.store.ListCiphers(ctx, a.UserID)
	if err != nil {
		s.fail(w, err, "sync")
		return
	}
	folders, err := s.store.ListFolders(ctx, a.UserID)
	if err != nil {
		s.fail(w, err, "sync")
		return
	}
	// SSH keys only for apps that know them (2024.12.0 and newer).
	sshOK := clientAtLeast(r, 2024, 12)
	cj := make([]any, 0, len(ciphers))
	for _, c := range ciphers {
		if c.Type == 5 && !sshOK {
			continue
		}
		cj = append(cj, bwCipher(c))
	}
	fj := make([]any, 0, len(folders))
	for _, f := range folders {
		fj = append(fj, bwFolder(f))
	}
	var domains any
	if !queryBool(r, "excludeDomains") {
		domains = s.bwDomainsJSON(a, true)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile": s.bwProfile(ctx, a), "folders": fj, "collections": []any{}, "policies": []any{}, "ciphers": cj, "domains": domains, "sends": []any{},
		"userDecryption": map[string]any{"masterPasswordUnlock": map[string]any{
			"kdf":                       map[string]any{"kdfType": a.KdfType, "iterations": a.KdfIterations, "memory": kdfNum(a.KdfMemory), "parallelism": kdfNum(a.KdfParallelism)},
			"masterKeyEncryptedUserKey": a.AKey, "masterKeyWrappedUserKey": a.AKey, "salt": a.Email,
		}, "userKeyId": nilIfEmpty(s.store.UserKeyID(ctx, a.UserID))},
		"object": "sync",
	})
}

// clientAtLeast reads the app version header (Bitwarden-Client-Version).
func clientAtLeast(r *http.Request, year, month int) bool {
	v := r.Header.Get("Bitwarden-Client-Version")
	if v == "" {
		return true // our own web vault and unknown apps get everything
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return true
	}
	y, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return true
	}
	return y > year || (y == year && m >= month)
}

func (s *Server) handleBWProfile(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.bwProfile(r.Context(), bwFrom(r.Context()).acct))
}

func (s *Server) handleBWPutProfile(w http.ResponseWriter, r *http.Request) {
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	a := bwFrom(r.Context()).acct
	name := strings.TrimSpace(jStr(in, "name"))
	if len(name) > 50 {
		bwErr(w, http.StatusBadRequest, "The field Name must be a string with a maximum length of 50.")
		return
	}
	a.Name = name
	if err := s.store.SaveVaultAccount(r.Context(), a); err != nil {
		s.fail(w, err, "save profile")
		return
	}
	writeJSON(w, http.StatusOK, s.bwProfile(r.Context(), a))
}

func (s *Server) handleBWAvatar(w http.ResponseWriter, r *http.Request) {
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	a := bwFrom(r.Context()).acct
	a.AvatarColor = jStrPtr(in, "avatarColor")
	if a.AvatarColor != nil && (len(*a.AvatarColor) != 7 || !strings.HasPrefix(*a.AvatarColor, "#")) {
		bwErr(w, http.StatusBadRequest, "The avatar color is a colour like #1a2b3c.")
		return
	}
	if err := s.store.SaveVaultAccount(r.Context(), a); err != nil {
		s.fail(w, err, "save avatar")
		return
	}
	writeJSON(w, http.StatusOK, s.bwProfile(r.Context(), a))
}

func (s *Server) handleRevisionDate(w http.ResponseWriter, r *http.Request) {
	a := bwFrom(r.Context()).acct
	t, err := time.Parse(time.RFC3339Nano, a.RevisionDate)
	if err != nil {
		t = time.Now()
	}
	writeJSON(w, http.StatusOK, t.UnixMilli())
}

func (s *Server) handleBWKeys(w http.ResponseWriter, r *http.Request) {
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	a := bwFrom(r.Context()).acct
	priv, pub := jStr(in, "encryptedPrivateKey"), jStr(in, "publicKey")
	if priv == "" || pub == "" {
		bwErr(w, http.StatusBadRequest, "Both keys are needed.")
		return
	}
	if a.PrivateKey != "" && a.PrivateKey != priv {
		bwErr(w, http.StatusBadRequest, "This vault already has keys.")
		return
	}
	a.PrivateKey, a.PublicKey = priv, pub
	if err := s.store.SaveVaultAccount(r.Context(), a); err != nil {
		s.fail(w, err, "save keys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"privateKey": a.PrivateKey, "publicKey": a.PublicKey, "object": "keys"})
}

// handleBWPassword changes the master password: the app sends the user key
// re-encrypted with the new master key and the new hash. Every other app is
// signed out.
func (s *Server) handleBWPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	a := b.acct
	if !s.checkSecret(ctx, a, in) {
		s.noteFailure(ctx, clientIP(r), a, "signin_failed", b.device.Name)
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	newHash, key := jStr(in, "newMasterPasswordHash"), jStr(in, "key")
	if newHash == "" || key == "" {
		bwErr(w, http.StatusBadRequest, "The new master password hash and key are needed.")
		return
	}
	if err := s.setMaster(ctx, a, newHash, key, jStr(in, "masterPasswordHint")); err != nil {
		s.fail(w, err, "change password")
		return
	}
	s.afterMasterChange(ctx, a, b.device, "password_changed", "Your master password was changed",
		"The master password of your vault was changed from "+b.device.Name+". Every app was signed out and needs the new password.")
	w.WriteHeader(http.StatusOK)
}

// setMaster stores a new master password hash and key and a new security
// stamp (which ends every session).
func (s *Server) setMaster(ctx context.Context, a *store.VaultAccount, clientHash, key, hint string) error {
	a.MasterSalt = bw.RandomBytes(64)
	a.MasterIterations = 600000
	a.MasterHash = bw.HashMaster(clientHash, a.MasterSalt, a.MasterIterations)
	a.AKey = key
	a.PasswordHint = strings.TrimSpace(hint)
	a.SecurityStamp = uuid.NewString()
	a.StampException = ""
	if err := s.store.SaveVaultAccount(ctx, a); err != nil {
		return err
	}
	return s.store.RotateRefreshTokens(ctx, a.UserID)
}

func (s *Server) afterMasterChange(ctx context.Context, a *store.VaultAccount, dev *store.Device, kind, title, body string) {
	devName := ""
	if dev != nil {
		devName = dev.Name
	}
	s.store.AddVaultEvent(ctx, a.UserID, store.VaultEvent{Kind: kind, DeviceName: devName})
	s.bwNotifyUser(a, bw.LogOut, dev)
	s.securityAlert(ctx, a.UserID, "security", title, body, "warning")
	s.publish(ctx, a.UserID, "vault.security_changed", a.UUID, map[string]any{"change": kind})
}

func (s *Server) handleBWKdf(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	a := b.acct
	if !s.checkSecret(ctx, a, in) {
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	auth, unlock := jMap(in, "authenticationData"), jMap(in, "unlockData")
	var kdf map[string]any
	var newHash, key string
	if auth != nil && unlock != nil {
		if jStr(auth, "salt") != a.Email || jStr(unlock, "salt") != a.Email {
			bwErr(w, http.StatusBadRequest, "Invalid master password salt")
			return
		}
		ak, uk := jMap(auth, "kdf"), jMap(unlock, "kdf")
		ab, _ := json.Marshal(ak)
		ub, _ := json.Marshal(uk)
		if string(ab) != string(ub) {
			bwErr(w, http.StatusBadRequest, "KDF settings must be equal for authentication and unlock")
			return
		}
		kdf = uk
		newHash, key = jStr(auth, "masterPasswordAuthenticationHash"), jStr(unlock, "masterKeyWrappedUserKey")
	} else { // older apps
		kdf = map[string]any{"kdfType": in["kdf"], "iterations": in["kdfIterations"], "memory": in["kdfMemory"], "parallelism": in["kdfParallelism"]}
		newHash, key = jStr(in, "newMasterPasswordHash"), jStr(in, "key")
	}
	if newHash == "" || key == "" {
		bwErr(w, http.StatusBadRequest, "The new hash and key are needed.")
		return
	}
	t, iter := jInt(kdf, "kdfType", -1), jInt(kdf, "iterations", 0)
	switch t {
	case 0:
		if iter < 100000 {
			bwErr(w, http.StatusBadRequest, "PBKDF2 KDF iterations must be at least 100000.")
			return
		}
		a.KdfMemory, a.KdfParallelism = nil, nil
	case 1:
		m, p := jInt(kdf, "memory", 0), jInt(kdf, "parallelism", 0)
		if iter < 1 || m < 15 || m > 1024 || p < 1 || p > 16 {
			bwErr(w, http.StatusBadRequest, "Argon2id needs at least 1 iteration, 15–1024 MB of memory and 1–16 threads.")
			return
		}
		a.KdfMemory, a.KdfParallelism = &m, &p
	default:
		bwErr(w, http.StatusBadRequest, "Unknown KDF.")
		return
	}
	a.KdfType, a.KdfIterations = t, iter
	if err := s.setMaster(ctx, a, newHash, key, a.PasswordHint); err != nil {
		s.fail(w, err, "change kdf")
		return
	}
	s.afterMasterChange(ctx, a, b.device, "kdf_changed", "Your vault's key settings changed",
		"The KDF settings of your vault were changed from "+b.device.Name+". Every app was signed out.")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBWSecurityStamp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	if !s.checkSecret(ctx, b.acct, in) {
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	if err := s.signOutEverywhere(ctx, b.acct); err != nil {
		s.fail(w, err, "sign out")
		return
	}
	s.store.AddVaultEvent(ctx, b.acct.UserID, store.VaultEvent{Kind: "signed_out_everywhere", DeviceName: b.device.Name})
	s.bwNotifyUser(b.acct, bw.LogOut, b.device)
	w.WriteHeader(http.StatusOK)
}

// signOutEverywhere ends every app's session (new stamp, new refresh tokens).
func (s *Server) signOutEverywhere(ctx context.Context, a *store.VaultAccount) error {
	a.SecurityStamp = uuid.NewString()
	a.StampException = ""
	if err := s.store.SaveVaultAccount(ctx, a); err != nil {
		return err
	}
	return s.store.RotateRefreshTokens(ctx, a.UserID)
}

func (s *Server) handleBWVerifyPassword(w http.ResponseWriter, r *http.Request) {
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(r.Context())
	if !s.checkSecret(r.Context(), b.acct, in) {
		s.noteFailure(r.Context(), clientIP(r), b.acct, "signin_failed", b.device.Name)
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "masterPasswordPolicy"})
}

func (s *Server) handleBWDeleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	if !s.checkSecret(ctx, b.acct, in) {
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	if err := s.store.DeleteVault(ctx, b.acct.UserID); err != nil {
		s.fail(w, err, "delete vault")
		return
	}
	s.bwNotifyUser(b.acct, bw.LogOut, nil)
	s.log.Info("vault deleted from an app", "user", b.acct.UserID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBWPublicKey(w http.ResponseWriter, r *http.Request) {
	a := bwFrom(r.Context()).acct
	if !strings.EqualFold(chiParam(r, "id"), a.UUID) || a.PublicKey == "" {
		bwErr(w, http.StatusNotFound, "User doesn't exist")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"userId": a.UUID, "publicKey": a.PublicKey, "object": "userKey"})
}

// ---- devices ----

func (s *Server) handleBWDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.store.ListDevices(r.Context(), bwFrom(r.Context()).acct.UserID)
	if err != nil {
		s.fail(w, err, "devices")
		return
	}
	out := make([]any, 0, len(devs))
	for _, d := range devs {
		out = append(out, bwDevice(d))
	}
	writeJSON(w, http.StatusOK, bwList(out))
}

func (s *Server) handleBWDevice(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDevice(r.Context(), bwFrom(r.Context()).acct.UserID, strings.ToLower(chiParam(r, "id")))
	if err != nil {
		bwErr(w, http.StatusNotFound, "No device found")
		return
	}
	writeJSON(w, http.StatusOK, bwDevice(*d))
}

func (s *Server) handleBWPushToken(w http.ResponseWriter, r *http.Request) {
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(r.Context())
	d, err := s.store.GetDevice(r.Context(), b.acct.UserID, strings.ToLower(chiParam(r, "id")))
	if err != nil {
		bwErr(w, http.StatusNotFound, "No device found")
		return
	}
	d.PushToken = jStr(in, "pushToken")
	if err := s.store.SaveDevice(r.Context(), d, false); err != nil {
		s.fail(w, err, "save device")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBWClearPushToken(w http.ResponseWriter, r *http.Request) {
	b := bwFrom(r.Context())
	if d, err := s.store.GetDevice(r.Context(), b.acct.UserID, strings.ToLower(chiParam(r, "id"))); err == nil {
		d.PushToken = ""
		_ = s.store.SaveDevice(r.Context(), d, false)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBWRemoveDevice(w http.ResponseWriter, r *http.Request) {
	b := bwFrom(r.Context())
	id := strings.ToLower(chiParam(r, "id"))
	d, err := s.store.GetDevice(r.Context(), b.acct.UserID, id)
	if err != nil {
		bwErr(w, http.StatusNotFound, "No device found")
		return
	}
	if err := s.store.DeleteDevice(r.Context(), b.acct.UserID, id); err != nil {
		s.fail(w, err, "remove device")
		return
	}
	s.store.AddVaultEvent(r.Context(), b.acct.UserID, store.VaultEvent{Kind: "device_removed", DeviceName: d.Name, DeviceType: &d.Type})
	w.WriteHeader(http.StatusOK)
}

// ---- items ----

func (s *Server) handleBWCiphers(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.ListCiphers(r.Context(), bwFrom(r.Context()).acct.UserID)
	if err != nil {
		s.fail(w, err, "ciphers")
		return
	}
	out := make([]any, 0, len(cs))
	for _, c := range cs {
		out = append(out, bwCipher(c))
	}
	writeJSON(w, http.StatusOK, bwList(out))
}

func (s *Server) handleBWCipher(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetCipher(r.Context(), bwFrom(r.Context()).acct.UserID, chiParam(r, "id"))
	if err != nil {
		bwErr(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	writeJSON(w, http.StatusOK, bwCipher(*c))
}

// applyCipher copies what an app sent onto an item. The type's own object
// is kept whole (passkeys and other new fields survive) minus "response".
func (s *Server) applyCipher(ctx context.Context, uid int64, c *store.Cipher, in map[string]any) error {
	if org := jStr(in, "organizationId"); org != "" {
		return errors.New(noSharing)
	}
	t := jInt(in, "type", 0)
	key, ok := cipherTypeKeys[t]
	if !ok {
		return errors.New("Invalid type")
	}
	data := jMap(in, key)
	if data == nil {
		return errors.New("Data missing")
	}
	delete(data, "response")
	if uris, ok := data["uris"].([]any); ok {
		for _, u := range uris {
			if um, ok := u.(map[string]any); ok {
				delete(um, "response")
			}
		}
	}
	name := jStr(in, "name")
	if name == "" {
		return errors.New("The Name field is required.")
	}
	notes := jStrPtr(in, "notes")
	if notes != nil && len(*notes) > 50000 {
		return errors.New("The field Notes exceeds the maximum encrypted value length of 10000 characters.")
	}
	var folder *string
	if f := strings.ToLower(jStr(in, "folderId")); f != "" {
		if _, err := s.store.GetFolder(ctx, uid, f); err != nil {
			return errors.New("Invalid folder")
		}
		folder = &f
	}
	var fields any
	if fl := jList(in, "fields"); fl != nil {
		for _, f := range fl {
			if fm, ok := f.(map[string]any); ok {
				delete(fm, "response")
			}
		}
		fields = fl
	}
	var hist any
	if h, ok := in["passwordHistory"].([]any); ok {
		hist = h
	}
	db, _ := json.Marshal(data)
	c.Type = t
	c.Key = jStrPtr(in, "key")
	c.Name = name
	c.Notes = notes
	c.Fields = jsonText(fields)
	c.Data = string(db)
	c.PasswordHistory = jsonText(hist)
	c.Reprompt = jInt(in, "reprompt", 0)
	if c.Reprompt != 1 {
		c.Reprompt = 0
	}
	c.FolderUUID = folder
	c.Favorite = jBool(in, "favorite")
	if ad := fixDate(jStr(in, "archivedDate")); ad != "" {
		c.ArchivedAt = &ad
	} else if _, sent := in["archivedDate"]; sent {
		c.ArchivedAt = nil
	}
	return nil
}

func (s *Server) handleBWCreateCipher(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if c := jMap(in, "cipher"); c != nil { // /ciphers/create wraps it with collectionIds
		if len(jStrings(in, "collectionIds")) > 0 {
			bwErr(w, http.StatusBadRequest, noSharing)
			return
		}
		in = c
	}
	b := bwFrom(ctx)
	c := &store.Cipher{UserID: b.acct.UserID, UUID: uuid.NewString()}
	if err := s.applyCipher(ctx, b.acct.UserID, c, in); err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SaveCipher(ctx, c, false); err != nil {
		s.fail(w, err, "save item")
		return
	}
	s.cipherChanged(ctx, b, c, bw.SyncCipherCreate)
	writeJSON(w, http.StatusOK, bwCipher(*c))
}

func (s *Server) handleBWUpdateCipher(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	c, err := s.store.GetCipher(ctx, b.acct.UserID, chiParam(r, "id"))
	if err != nil {
		bwErr(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	// An app editing an old copy would overwrite newer changes: refuse.
	if lk := jStr(in, "lastKnownRevisionDate"); lk != "" {
		if t, err := time.Parse(time.RFC3339Nano, lk); err == nil {
			if cur, err := time.Parse(time.RFC3339Nano, store.BWDate(c.UpdatedAt)); err == nil && cur.Sub(t) > time.Second {
				bwErr(w, http.StatusBadRequest, "The client copy of this cipher is out of date. Resync the client and try again.")
				return
			}
		}
	}
	if err := s.applyCipher(ctx, b.acct.UserID, c, in); err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SaveCipher(ctx, c, false); err != nil {
		s.fail(w, err, "save item")
		return
	}
	s.cipherChanged(ctx, b, c, bw.SyncCipherUpdate)
	writeJSON(w, http.StatusOK, bwCipher(*c))
}

func (s *Server) handleBWPartial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	c, err := s.store.GetCipher(ctx, b.acct.UserID, chiParam(r, "id"))
	if err != nil {
		bwErr(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	c.FolderUUID = nil
	if f := strings.ToLower(jStr(in, "folderId")); f != "" {
		if _, err := s.store.GetFolder(ctx, b.acct.UserID, f); err != nil {
			bwErr(w, http.StatusBadRequest, "Invalid folder")
			return
		}
		c.FolderUUID = &f
	}
	c.Favorite = jBool(in, "favorite")
	if err := s.store.SaveCipher(ctx, c, false); err != nil {
		s.fail(w, err, "save item")
		return
	}
	s.cipherChanged(ctx, b, c, bw.SyncCipherUpdate)
	writeJSON(w, http.StatusOK, bwCipher(*c))
}

// handleBWDeleteCipher moves an item to the bin (soft) or deletes it.
func (s *Server) handleBWDeleteCipher(soft bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		b := bwFrom(ctx)
		c, err := s.store.GetCipher(ctx, b.acct.UserID, chiParam(r, "id"))
		if err != nil {
			bwErr(w, http.StatusNotFound, "Cipher doesn't exist")
			return
		}
		if err := s.deleteOne(ctx, b, c, soft); err != nil {
			s.fail(w, err, "delete item")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) deleteOne(ctx context.Context, b *bwSession, c *store.Cipher, soft bool) error {
	if soft {
		now := store.BWNow()
		c.DeletedAt = &now
		if err := s.store.SaveCipher(ctx, c, false); err != nil {
			return err
		}
		s.cipherChanged(ctx, b, c, bw.SyncCipherUpdate)
		return nil
	}
	if err := s.store.DeleteCipher(ctx, b.acct.UserID, c.UUID); err != nil {
		return err
	}
	_ = s.store.DeleteReminder(ctx, b.acct.UserID, c.UUID)
	s.cipherChanged(ctx, b, c, bw.SyncLoginDelete)
	return nil
}

func (s *Server) handleBWDeleteMany(soft bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		in, err := readBWJSON(r)
		if err != nil {
			bwErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		b := bwFrom(ctx)
		for _, id := range jStrings(in, "ids") {
			c, err := s.store.GetCipher(ctx, b.acct.UserID, id)
			if err != nil {
				continue
			}
			if err := s.deleteOne(ctx, b, c, soft); err != nil {
				s.fail(w, err, "delete items")
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) handleBWRestore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b := bwFrom(ctx)
	c, err := s.store.GetCipher(ctx, b.acct.UserID, chiParam(r, "id"))
	if err != nil {
		bwErr(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	c.DeletedAt = nil
	if err := s.store.SaveCipher(ctx, c, false); err != nil {
		s.fail(w, err, "restore item")
		return
	}
	s.cipherChanged(ctx, b, c, bw.SyncCipherUpdate)
	writeJSON(w, http.StatusOK, bwCipher(*c))
}

func (s *Server) handleBWRestoreMany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	out := []any{}
	for _, id := range jStrings(in, "ids") {
		c, err := s.store.GetCipher(ctx, b.acct.UserID, id)
		if err != nil {
			continue
		}
		c.DeletedAt = nil
		if err := s.store.SaveCipher(ctx, c, false); err != nil {
			s.fail(w, err, "restore items")
			return
		}
		s.cipherChanged(ctx, b, c, bw.SyncCipherUpdate)
		out = append(out, bwCipher(*c))
	}
	writeJSON(w, http.StatusOK, bwList(out))
}

func (s *Server) handleBWArchive(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		b := bwFrom(ctx)
		c, err := s.store.GetCipher(ctx, b.acct.UserID, chiParam(r, "id"))
		if err != nil {
			bwErr(w, http.StatusNotFound, "Cipher doesn't exist")
			return
		}
		setArchived(c, on)
		if err := s.store.SaveCipher(ctx, c, false); err != nil {
			s.fail(w, err, "archive item")
			return
		}
		s.cipherChanged(ctx, b, c, bw.SyncCipherUpdate)
		writeJSON(w, http.StatusOK, bwCipher(*c))
	}
}

func setArchived(c *store.Cipher, on bool) {
	if on {
		now := store.BWNow()
		c.ArchivedAt = &now
	} else {
		c.ArchivedAt = nil
	}
}

func (s *Server) handleBWArchiveMany(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		in, err := readBWJSON(r)
		if err != nil {
			bwErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		b := bwFrom(ctx)
		out := []any{}
		for _, id := range jStrings(in, "ids") {
			c, err := s.store.GetCipher(ctx, b.acct.UserID, id)
			if err != nil {
				continue
			}
			setArchived(c, on)
			if err := s.store.SaveCipher(ctx, c, false); err != nil {
				s.fail(w, err, "archive items")
				return
			}
			s.cipherChanged(ctx, b, c, bw.SyncCipherUpdate)
			out = append(out, bwCipher(*c))
		}
		writeJSON(w, http.StatusOK, bwList(out))
	}
}

func (s *Server) handleBWMove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	var folder *string
	if f := strings.ToLower(jStr(in, "folderId")); f != "" {
		if _, err := s.store.GetFolder(ctx, b.acct.UserID, f); err != nil {
			bwErr(w, http.StatusBadRequest, "Invalid folder")
			return
		}
		folder = &f
	}
	for _, id := range jStrings(in, "ids") {
		c, err := s.store.GetCipher(ctx, b.acct.UserID, id)
		if err != nil {
			continue
		}
		c.FolderUUID = folder
		if err := s.store.SaveCipher(ctx, c, false); err != nil {
			s.fail(w, err, "move items")
			return
		}
		s.cipherChanged(ctx, b, c, bw.SyncCipherUpdate)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBWPurge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	if r.URL.Query().Get("organizationId") != "" {
		bwErr(w, http.StatusBadRequest, noSharing)
		return
	}
	if !s.checkSecret(ctx, b.acct, in) {
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	if err := s.store.PurgeVault(ctx, b.acct.UserID); err != nil {
		s.fail(w, err, "purge")
		return
	}
	s.store.TouchVault(ctx, b.acct.UserID)
	s.store.AddVaultEvent(ctx, b.acct.UserID, store.VaultEvent{Kind: "purged", DeviceName: b.device.Name})
	s.bwNotifyUser(b.acct, bw.SyncVault, nil)
	w.WriteHeader(http.StatusOK)
}

// handleBWImport takes the apps' import (already encrypted on the device):
// folders, items and which item goes in which folder.
func (s *Server) handleBWImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	uid := b.acct.UserID
	folders := jList(in, "folders")
	ciphers := jList(in, "ciphers")
	if len(ciphers) > 20000 {
		bwErr(w, http.StatusBadRequest, "That's more than 20,000 items at once.")
		return
	}
	existing, _ := s.store.ListFolders(ctx, uid)
	have := map[string]bool{}
	for _, f := range existing {
		have[f.UUID] = true
	}
	folderIDs := make([]string, len(folders))
	for i, f := range folders {
		fm, _ := f.(map[string]any)
		if fm == nil {
			continue
		}
		id := strings.ToLower(jStr(fm, "id"))
		if id != "" && have[id] {
			folderIDs[i] = id
			continue
		}
		nf := &store.Folder{UserID: uid, UUID: uuid.NewString(), Name: jStr(fm, "name")}
		if nf.Name == "" {
			continue
		}
		if err := s.store.SaveFolder(ctx, nf); err != nil {
			s.fail(w, err, "import folders")
			return
		}
		folderIDs[i] = nf.UUID
	}
	rel := map[int]string{}
	for _, x := range jList(in, "folderRelationships") {
		xm, _ := x.(map[string]any)
		if xm == nil {
			continue
		}
		ci, fi := jInt(xm, "key", -1), jInt(xm, "value", -1)
		if fi >= 0 && fi < len(folderIDs) && folderIDs[fi] != "" {
			rel[ci] = folderIDs[fi]
		}
	}
	for i, x := range ciphers {
		cm, _ := x.(map[string]any)
		if cm == nil {
			continue
		}
		delete(cm, "folderId")
		c := &store.Cipher{UserID: uid, UUID: uuid.NewString()}
		if err := s.applyCipher(ctx, uid, c, cm); err != nil {
			bwErr(w, http.StatusBadRequest, "Item "+jsonNum(i+1)+": "+err.Error())
			return
		}
		if f, ok := rel[i]; ok {
			c.FolderUUID = &f
		}
		if err := s.store.SaveCipher(ctx, c, false); err != nil {
			s.fail(w, err, "import items")
			return
		}
	}
	s.store.TouchVault(ctx, uid)
	s.store.AddVaultEvent(ctx, uid, store.VaultEvent{Kind: "imported", DeviceName: b.device.Name, Detail: jsonNum(len(ciphers)) + " items"})
	s.bwNotifyUser(b.acct, bw.SyncVault, nil)
	w.WriteHeader(http.StatusOK)
}

func jsonNum(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// cipherChanged bumps the vault's revision and tells the other apps.
func (s *Server) cipherChanged(ctx context.Context, b *bwSession, c *store.Cipher, kind int) {
	s.store.TouchVault(ctx, b.acct.UserID)
	t, _ := time.Parse(time.RFC3339Nano, store.BWDate(c.UpdatedAt))
	s.bw.hub.send(b.acct.UUID, bw.UpdateFrame(kind, deviceID(b.device), bw.Map{
		{K: "Id", V: c.UUID}, {K: "UserId", V: b.acct.UUID}, {K: "OrganizationId", V: bw.Nil{}}, {K: "CollectionIds", V: bw.Nil{}}, {K: "RevisionDate", V: bw.Timestamp(t)},
	}))
}

func deviceID(d *store.Device) string {
	if d == nil {
		return ""
	}
	return d.UUID
}

// bwNotifyUser tells every app of a vault to sync (or to sign out).
func (s *Server) bwNotifyUser(a *store.VaultAccount, kind int, dev *store.Device) {
	s.bw.hub.send(a.UUID, bw.UpdateFrame(kind, deviceID(dev), bw.Map{{K: "UserId", V: a.UUID}, {K: "Date", V: bw.Timestamp(time.Now())}}))
}

// ---- folders ----

func (s *Server) handleBWFolders(w http.ResponseWriter, r *http.Request) {
	fs, err := s.store.ListFolders(r.Context(), bwFrom(r.Context()).acct.UserID)
	if err != nil {
		s.fail(w, err, "folders")
		return
	}
	out := make([]any, 0, len(fs))
	for _, f := range fs {
		out = append(out, bwFolder(f))
	}
	writeJSON(w, http.StatusOK, bwList(out))
}

func (s *Server) handleBWFolder(w http.ResponseWriter, r *http.Request) {
	f, err := s.store.GetFolder(r.Context(), bwFrom(r.Context()).acct.UserID, strings.ToLower(chiParam(r, "id")))
	if err != nil {
		bwErr(w, http.StatusNotFound, "Invalid folder")
		return
	}
	writeJSON(w, http.StatusOK, bwFolder(*f))
}

func (s *Server) handleBWSaveFolder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	name := jStr(in, "name")
	if name == "" {
		bwErr(w, http.StatusBadRequest, "The Name field is required.")
		return
	}
	kind := bw.SyncFolderCreate
	f := &store.Folder{UserID: b.acct.UserID, UUID: uuid.NewString()}
	if id := strings.ToLower(chiParam(r, "id")); id != "" {
		cur, err := s.store.GetFolder(ctx, b.acct.UserID, id)
		if err != nil {
			bwErr(w, http.StatusNotFound, "Invalid folder")
			return
		}
		f, kind = cur, bw.SyncFolderUpdate
	} else if id := strings.ToLower(jStr(in, "id")); id != "" { // apps may pick the id
		if _, err := uuid.Parse(id); err == nil {
			f.UUID = id
		}
	}
	f.Name = name
	if err := s.store.SaveFolder(ctx, f); err != nil {
		if errors.Is(err, store.ErrConflict) {
			bwErr(w, http.StatusBadRequest, "Invalid folder")
			return
		}
		s.fail(w, err, "save folder")
		return
	}
	s.folderChanged(ctx, b, f, kind)
	writeJSON(w, http.StatusOK, bwFolder(*f))
}

func (s *Server) handleBWDeleteFolder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b := bwFrom(ctx)
	f, err := s.store.GetFolder(ctx, b.acct.UserID, strings.ToLower(chiParam(r, "id")))
	if err != nil {
		bwErr(w, http.StatusNotFound, "Invalid folder")
		return
	}
	if err := s.store.DeleteFolder(ctx, b.acct.UserID, f.UUID); err != nil {
		s.fail(w, err, "delete folder")
		return
	}
	s.folderChanged(ctx, b, f, bw.SyncFolderDelete)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) folderChanged(ctx context.Context, b *bwSession, f *store.Folder, kind int) {
	s.store.TouchVault(ctx, b.acct.UserID)
	t, _ := time.Parse(time.RFC3339Nano, store.BWDate(f.UpdatedAt))
	s.bw.hub.send(b.acct.UUID, bw.UpdateFrame(kind, deviceID(b.device), bw.Map{{K: "Id", V: f.UUID}, {K: "UserId", V: b.acct.UUID}, {K: "RevisionDate", V: bw.Timestamp(t)}}))
}

// ---- two-step login ----

func (s *Server) handleBWTwoFactor(w http.ResponseWriter, r *http.Request) {
	tfs, err := s.store.ListTwoFactor(r.Context(), bwFrom(r.Context()).acct.UserID)
	if err != nil {
		s.fail(w, err, "two-step login")
		return
	}
	out := []any{}
	for _, t := range tfs {
		if t.Type == tfAuthenticator {
			out = append(out, map[string]any{"enabled": t.Enabled, "type": t.Type, "object": "twoFactorProvider"})
		}
	}
	writeJSON(w, http.StatusOK, bwList(out))
}

func (s *Server) handleBWGetAuthenticator(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	a := bwFrom(ctx).acct
	if !s.checkSecret(ctx, a, in) {
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	enabled, key := false, bw.RandomBase32(20)
	if t, err := s.store.GetTwoFactor(ctx, a.UserID, tfAuthenticator); err == nil && t.Enabled {
		enabled, key = true, t.Data
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "key": key, "object": "twoFactorAuthenticator"})
}

func (s *Server) handleBWEnableAuthenticator(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	a := b.acct
	if !s.checkSecret(ctx, a, in) {
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	key := strings.ToUpper(strings.ReplaceAll(jStr(in, "key"), " ", ""))
	if len(key) != 32 {
		bwErr(w, http.StatusBadRequest, "Invalid key length")
		return
	}
	step, ok := bw.CheckTOTP(key, jStr(in, "token"), 0, time.Now())
	if !ok {
		bwErr(w, http.StatusBadRequest, "That code isn't right. Check the time on your phone and try the next code.")
		return
	}
	if err := s.store.SaveTwoFactor(ctx, &store.TwoFactor{UserID: a.UserID, Type: tfAuthenticator, Enabled: true, Data: key, LastUsed: step}); err != nil {
		s.fail(w, err, "two-step login")
		return
	}
	if a.TotpRecover == "" {
		a.TotpRecover = bw.RandomBase32(20)
	}
	if err := s.store.SaveVaultAccount(ctx, a); err != nil {
		s.fail(w, err, "two-step login")
		return
	}
	s.store.AddVaultEvent(ctx, a.UserID, store.VaultEvent{Kind: "twofactor_on", DeviceName: b.device.Name})
	s.securityAlert(ctx, a.UserID, "security", "Two-step login is on", "Signing in to your vault now also asks for a code from your authenticator app.", "info")
	s.publish(ctx, a.UserID, "vault.security_changed", a.UUID, map[string]any{"change": "twofactor_on"})
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "key": key, "object": "twoFactorAuthenticator"})
}

func (s *Server) handleBWDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := bwFrom(ctx)
	a := b.acct
	if !s.checkSecret(ctx, a, in) {
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	t := jInt(in, "type", tfAuthenticator)
	if err := s.store.DeleteTwoFactor(ctx, a.UserID, t); err != nil {
		s.fail(w, err, "two-step login")
		return
	}
	s.store.AddVaultEvent(ctx, a.UserID, store.VaultEvent{Kind: "twofactor_off", DeviceName: b.device.Name})
	s.securityAlert(ctx, a.UserID, "security", "Two-step login is off", "Signing in to your vault no longer asks for a code. If that wasn't you, change your master password.", "warning")
	s.publish(ctx, a.UserID, "vault.security_changed", a.UUID, map[string]any{"change": "twofactor_off"})
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "type": t, "object": "twoFactorProvider"})
}

func (s *Server) handleBWGetRecover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	a := bwFrom(ctx).acct
	if !s.checkSecret(ctx, a, in) {
		bwErr(w, http.StatusBadRequest, "Invalid password")
		return
	}
	var code any
	if a.TotpRecover != "" {
		code = a.TotpRecover
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "object": "twoFactorRecover"})
}

// ---- equivalent domains ----

func (s *Server) bwDomainsJSON(a *store.VaultAccount, noExcluded bool) map[string]any {
	var eq any = []any{}
	_ = json.Unmarshal([]byte(a.EquivalentDomains), &eq)
	if eq == nil {
		eq = []any{}
	}
	var ex []int
	_ = json.Unmarshal([]byte(a.ExcludedGlobals), &ex)
	off := map[int]bool{}
	for _, t := range ex {
		off[t] = true
	}
	globals := []any{}
	for _, g := range s.globalDomains() {
		excluded := off[g.Type]
		if noExcluded && excluded {
			continue
		}
		globals = append(globals, map[string]any{"type": g.Type, "domains": g.Domains, "excluded": excluded})
	}
	return map[string]any{"equivalentDomains": eq, "globalEquivalentDomains": globals, "object": "domains"}
}

// globalDomain is one group of sites that share logins (google.com,
// youtube.com…), Bitwarden's built-in list.
type globalDomain struct {
	Type    int      `json:"type"`
	Domains []string `json:"domains"`
}

// globalDomains reads GLOBAL_DOMAINS_FILE once (for example Vaultwarden's
// global_domains.json). Without it only a person's own rules apply.
func (s *Server) globalDomains() []globalDomain {
	s.domainsOnce.Do(func() {
		if s.cfg.GlobalDomainsFile == "" {
			return
		}
		b, err := os.ReadFile(s.cfg.GlobalDomainsFile)
		if err != nil {
			s.log.Warn("global domains file not read", "path", s.cfg.GlobalDomainsFile, "err", err)
			return
		}
		if err := json.Unmarshal(b, &s.domains); err != nil {
			s.log.Warn("global domains file not valid", "err", err)
			s.domains = nil
		}
	})
	return s.domains
}

func (s *Server) handleBWDomains(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.bwDomainsJSON(bwFrom(r.Context()).acct, false))
}

func (s *Server) handleBWPutDomains(w http.ResponseWriter, r *http.Request) {
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	a := bwFrom(r.Context()).acct
	eq := jList(in, "equivalentDomains")
	if eq == nil {
		eq = []any{}
	}
	ex := jList(in, "excludedGlobalEquivalentDomains")
	if ex == nil {
		ex = []any{}
	}
	a.EquivalentDomains = *jsonText(eq)
	a.ExcludedGlobals = *jsonText(ex)
	if err := s.store.SaveVaultAccount(r.Context(), a); err != nil {
		s.fail(w, err, "save domains")
		return
	}
	s.bwNotifyUser(a, bw.SyncSettings, bwFrom(r.Context()).device)
	writeJSON(w, http.StatusOK, map[string]any{})
}

// handleBWUserKeyID records the id newer apps give the user key (only an
// id, no key material), so they stop asking.
func (s *Server) handleBWUserKeyID(w http.ResponseWriter, r *http.Request) {
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	s.log.Debug("user key id", "fields", keys)
	id := jStr(in, "userKeyId")
	if id == "" {
		id = jStr(in, "keyId")
	}
	if id == "" || len(id) > 200 {
		bwErr(w, http.StatusBadRequest, "A key id is needed.")
		return
	}
	b := bwFrom(r.Context())
	if err := s.store.SetUserKeyID(r.Context(), b.acct.UserID, id); err != nil {
		s.fail(w, err, "user key id")
		return
	}
	w.WriteHeader(http.StatusOK)
}
