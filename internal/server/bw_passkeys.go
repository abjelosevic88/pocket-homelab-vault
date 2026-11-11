package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// Passkeys that sign in, the way Bitwarden's "log in with passkey" works:
//
//   - /api/webauthn… (signed in) adds, lists, updates and removes them;
//     adding asks for the master password.
//   - /identity/accounts/webauthn/assertion-options + grant_type=webauthn
//     sign in with one, no email or password, and no second step (the
//     passkey already is something you have plus your fingerprint or PIN).
//   - A passkey made with the PRF extension also unlocks: the browser gets a
//     secret from it that only it can make again, turns that into a key and
//     sends back three things it encrypted: a fresh RSA private key (with
//     that key), its public key (with the user key) and the user key (with
//     the public key). The server keeps them and hands the first and the
//     last back after a good sign-in. It can open none of them.
//
// The ceremony state rides in a signed token (5 minutes), and each
// challenge works once.

const (
	maxPasskeys  = 10
	passkeyTTL   = 5 * time.Minute
	prfEnabled   = 0 // Bitwarden's WebAuthnPrfStatus
	prfSupported = 1
	prfNone      = 2
)

type passkeyClaims struct {
	Nbf     int64                `json:"nbf"`
	Exp     int64                `json:"exp"`
	Iss     string               `json:"iss"`
	Sub     string               `json:"sub"` // passkey-create | passkey-login | passkey-update
	User    string               `json:"user,omitempty"`
	Session webauthn.SessionData `json:"session"`
}

// usedChallenges stops a challenge working twice.
var usedChallenges = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

func spendChallenge(ch string) bool {
	usedChallenges.Lock()
	defer usedChallenges.Unlock()
	now := time.Now()
	for k, t := range usedChallenges.m {
		if now.After(t) {
			delete(usedChallenges.m, k)
		}
	}
	if _, ok := usedChallenges.m[ch]; ok {
		return false
	}
	usedChallenges.m[ch] = now.Add(passkeyTTL + time.Minute)
	return true
}

// webAuthn is the relying party for this request: the vault's own address.
func (s *Server) webAuthn(r *http.Request) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(s.bwBase(r))
	if err != nil || u.Host == "" {
		return nil, errors.New("the vault's address isn't set")
	}
	return webauthn.New(&webauthn.Config{
		RPID: u.Hostname(), RPDisplayName: "Pocket Vault", RPOrigins: []string{u.Scheme + "://" + u.Host},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyTTL, TimeoutUVD: passkeyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyTTL, TimeoutUVD: passkeyTTL},
		},
	})
}

// passkeyUser is a vault as WebAuthn sees it. The user handle is the
// account's uuid, so a passkey names its vault without an email.
type passkeyUser struct {
	acct  *store.VaultAccount
	creds []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte   { return []byte(u.acct.UUID) }
func (u *passkeyUser) WebAuthnName() string { return u.acct.Email }
func (u *passkeyUser) WebAuthnDisplayName() string {
	if u.acct.Name != "" {
		return u.acct.Name
	}
	return u.acct.Email
}
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Server) passkeyUserFor(ctx context.Context, a *store.VaultAccount) (*passkeyUser, []store.Passkey, error) {
	pks, err := s.store.ListPasskeys(ctx, a.UserID)
	if err != nil {
		return nil, nil, err
	}
	u := &passkeyUser{acct: a}
	for _, p := range pks {
		var c webauthn.Credential
		if json.Unmarshal([]byte(p.Credential), &c) == nil {
			u.creds = append(u.creds, c)
		}
	}
	return u, pks, nil
}

func (s *Server) signPasskey(sub, user string, sess *webauthn.SessionData) (string, error) {
	now := time.Now()
	return bw.Sign(s.bwKey(), passkeyClaims{Nbf: now.Unix(), Exp: now.Add(passkeyTTL).Unix(), Iss: s.bw.issuer, Sub: sub, User: user, Session: *sess})
}

// readPasskeyToken checks a ceremony token and spends its challenge.
func (s *Server) readPasskeyToken(tok, sub, user string) (*passkeyClaims, bool) {
	var c passkeyClaims
	if tok == "" || bw.Verify(&s.bwKey().PublicKey, tok, s.bw.issuer, &c) != nil || c.Sub != sub || c.User != user {
		return nil, false
	}
	if !spendChallenge(c.Session.Challenge) {
		return nil, false
	}
	return &c, true
}

func passkeyJSON(p store.Passkey) map[string]any {
	st := prfNone
	if p.Unlocks() {
		st = prfEnabled
	} else if p.SupportsPRF {
		st = prfSupported
	}
	return map[string]any{
		"id": p.UUID, "name": p.Name, "prfStatus": st,
		"encryptedUserKey": nilIfEmpty(p.EncryptedUserKey), "encryptedPublicKey": nilIfEmpty(p.EncryptedPublicKey),
		"creationDate": store.BWDate(p.CreatedAt), "lastUsedDate": lastUsed(p.LastUsedAt),
		"object": "webauthnCredential",
	}
}

func lastUsed(p *string) any {
	if p == nil || *p == "" {
		return nil
	}
	return store.BWDate(*p)
}

var (
	rsaEncString = regexp.MustCompile(`^4\.[A-Za-z0-9+/=]+$`)
)

// passkeyKeys reads the three wrapped keys; all or none.
func passkeyKeys(in map[string]any) (user, pub, priv string, err error) {
	user, pub, priv = jStr(in, "encryptedUserKey"), jStr(in, "encryptedPublicKey"), jStr(in, "encryptedPrivateKey")
	if user == "" && pub == "" && priv == "" {
		return "", "", "", nil
	}
	if !rsaEncString.MatchString(user) || !encString.MatchString(pub) || !encString.MatchString(priv) {
		return "", "", "", errors.New("The keys for unlocking with this passkey are incomplete.")
	}
	return user, pub, priv, nil
}

// deviceResponse is the browser's answer, as JSON bytes.
func deviceResponse(in map[string]any) []byte {
	v, ok := in["deviceResponse"]
	if !ok {
		return nil
	}
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	b, _ := json.Marshal(v)
	return b
}

// ---- /api/webauthn ----

func (s *Server) handleBWPasskeys(w http.ResponseWriter, r *http.Request) {
	b := bwFrom(r.Context())
	pks, err := s.store.ListPasskeys(r.Context(), b.acct.UserID)
	if err != nil {
		s.fail(w, err, "passkeys")
		return
	}
	out := make([]any, 0, len(pks))
	for _, p := range pks {
		out = append(out, passkeyJSON(p))
	}
	writeJSON(w, http.StatusOK, bwList(out))
}

// handleBWPasskeyCreateOptions starts adding a passkey (master password needed).
func (s *Server) handleBWPasskeyCreateOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b := bwFrom(ctx)
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !s.checkSecret(ctx, b.acct, in) {
		s.noteFailure(ctx, clientIP(r), b.acct, "signin_failed", b.device.Name)
		bwErr(w, http.StatusBadRequest, "That master password isn't right.")
		return
	}
	user, pks, err := s.passkeyUserFor(ctx, b.acct)
	if err != nil {
		s.fail(w, err, "passkeys")
		return
	}
	if len(pks) >= maxPasskeys {
		bwErr(w, http.StatusBadRequest, "A vault can have up to 10 passkeys. Remove one first.")
		return
	}
	wa, err := s.webAuthn(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(user.creds))
	for _, c := range user.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, sess, err := wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		s.fail(w, err, "passkey options")
		return
	}
	tok, err := s.signPasskey("passkey-create", b.acct.UUID, sess)
	if err != nil {
		s.fail(w, err, "passkey options")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": opts.Response, "token": tok, "object": "webauthnCredentialCreateOptions"})
}

// handleBWPasskeyCreate saves the passkey the browser just made.
func (s *Server) handleBWPasskeyCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b := bwFrom(ctx)
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	claims, ok := s.readPasskeyToken(jStr(in, "token"), "passkey-create", b.acct.UUID)
	if !ok {
		bwErr(w, http.StatusBadRequest, "That took too long or was already used. Start again.")
		return
	}
	name := strings.TrimSpace(jStr(in, "name"))
	if name == "" {
		name = "Passkey"
	}
	if len([]rune(name)) > 50 {
		name = string([]rune(name)[:50])
	}
	ukey, pub, priv, err := passkeyKeys(in)
	if err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	user, pks, err := s.passkeyUserFor(ctx, b.acct)
	if err != nil {
		s.fail(w, err, "passkeys")
		return
	}
	if len(pks) >= maxPasskeys {
		bwErr(w, http.StatusBadRequest, "A vault can have up to 10 passkeys. Remove one first.")
		return
	}
	wa, err := s.webAuthn(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(deviceResponse(in))
	if err != nil {
		bwErr(w, http.StatusBadRequest, "The passkey's answer couldn't be read.")
		return
	}
	cred, err := wa.CreateCredential(user, claims.Session, parsed)
	if err != nil {
		s.log.Info("passkey not added", "err", err)
		bwErr(w, http.StatusBadRequest, "The passkey couldn't be checked. Try again.")
		return
	}
	raw, _ := json.Marshal(cred)
	p := &store.Passkey{UserID: b.acct.UserID, UUID: uuid.NewString(), Name: name, CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID), Credential: string(raw),
		SupportsPRF: jBool(in, "supportsPrf") || ukey != "", EncryptedUserKey: ukey, EncryptedPublicKey: pub, EncryptedPrivateKey: priv}
	if err := s.store.AddPasskey(ctx, p); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			bwErr(w, http.StatusBadRequest, "This passkey is already on a vault.")
			return
		}
		s.fail(w, err, "save passkey")
		return
	}
	s.store.AddVaultEvent(ctx, b.acct.UserID, store.VaultEvent{Kind: "passkey_added", DeviceName: b.device.Name, IP: clientIP(r), Detail: name})
	s.securityAlert(ctx, b.acct.UserID, "security", "Passkey added to your vault",
		"The passkey “"+name+"” can now sign in to your vault"+map[bool]string{true: " and unlock it", false: ""}[p.Unlocks()]+". If that wasn't you, remove it in Pocket Vault → Security.", "warning")
	s.publish(ctx, b.acct.UserID, "vault.security_changed", b.acct.UUID, map[string]any{"change": "passkey_added"})
	writeJSON(w, http.StatusOK, passkeyJSON(*p))
}

// handleBWPasskeyAssertionOptions starts turning on unlocking for a passkey
// that was added without it.
func (s *Server) handleBWPasskeyAssertionOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b := bwFrom(ctx)
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !s.checkSecret(ctx, b.acct, in) {
		bwErr(w, http.StatusBadRequest, "That master password isn't right.")
		return
	}
	user, _, err := s.passkeyUserFor(ctx, b.acct)
	if err != nil {
		s.fail(w, err, "passkeys")
		return
	}
	if len(user.creds) == 0 {
		bwErr(w, http.StatusBadRequest, "There are no passkeys on this vault yet.")
		return
	}
	wa, err := s.webAuthn(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	opts, sess, err := wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.fail(w, err, "passkey options")
		return
	}
	tok, err := s.signPasskey("passkey-update", b.acct.UUID, sess)
	if err != nil {
		s.fail(w, err, "passkey options")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": opts.Response, "token": tok, "object": "webAuthnLoginAssertionOptions"})
}

// handleBWPasskeyUpdate stores unlock keys for a passkey, proven by using it.
func (s *Server) handleBWPasskeyUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b := bwFrom(ctx)
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	claims, ok := s.readPasskeyToken(jStr(in, "token"), "passkey-update", b.acct.UUID)
	if !ok {
		bwErr(w, http.StatusBadRequest, "That took too long or was already used. Start again.")
		return
	}
	ukey, pub, priv, err := passkeyKeys(in)
	if err != nil || ukey == "" {
		bwErr(w, http.StatusBadRequest, "The keys for unlocking with this passkey are incomplete.")
		return
	}
	user, _, err := s.passkeyUserFor(ctx, b.acct)
	if err != nil {
		s.fail(w, err, "passkeys")
		return
	}
	wa, err := s.webAuthn(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(deviceResponse(in))
	if err != nil {
		bwErr(w, http.StatusBadRequest, "The passkey's answer couldn't be read.")
		return
	}
	cred, err := wa.ValidateLogin(user, claims.Session, parsed)
	if err != nil || cred.Authenticator.CloneWarning {
		bwErr(w, http.StatusBadRequest, "The passkey couldn't be checked. Try again.")
		return
	}
	p, err := s.store.GetPasskeyByCredential(ctx, base64.RawURLEncoding.EncodeToString(cred.ID))
	if err != nil || p.UserID != b.acct.UserID {
		bwErr(w, http.StatusBadRequest, "That passkey isn't on this vault.")
		return
	}
	raw, _ := json.Marshal(cred)
	p.Credential, p.SupportsPRF, p.EncryptedUserKey, p.EncryptedPublicKey, p.EncryptedPrivateKey = string(raw), true, ukey, pub, priv
	if err := s.store.SavePasskey(ctx, p); err != nil {
		s.fail(w, err, "save passkey")
		return
	}
	s.store.AddVaultEvent(ctx, b.acct.UserID, store.VaultEvent{Kind: "passkey_unlock_on", DeviceName: b.device.Name, IP: clientIP(r), Detail: p.Name})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBWPasskeyDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b := bwFrom(ctx)
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !s.checkSecret(ctx, b.acct, in) {
		bwErr(w, http.StatusBadRequest, "That master password isn't right.")
		return
	}
	p, err := s.store.GetPasskey(ctx, b.acct.UserID, chiParam(r, "id"))
	if err != nil {
		bwErr(w, http.StatusNotFound, "That passkey isn't on this vault.")
		return
	}
	if err := s.store.DeletePasskey(ctx, b.acct.UserID, p.UUID); err != nil {
		s.fail(w, err, "remove passkey")
		return
	}
	s.store.AddVaultEvent(ctx, b.acct.UserID, store.VaultEvent{Kind: "passkey_removed", DeviceName: b.device.Name, IP: clientIP(r), Detail: p.Name})
	s.publish(ctx, b.acct.UserID, "vault.security_changed", b.acct.UUID, map[string]any{"change": "passkey_removed"})
	w.WriteHeader(http.StatusOK)
}

// ---- /identity: signing in with one ----

func (s *Server) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	wa, err := s.webAuthn(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	opts, sess, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.fail(w, err, "passkey options")
		return
	}
	tok, err := s.signPasskey("passkey-login", "", sess)
	if err != nil {
		s.fail(w, err, "passkey options")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": opts.Response, "token": tok, "object": "webAuthnLoginAssertionOptions"})
}

func (s *Server) passkeyLogin(w http.ResponseWriter, r *http.Request, in loginForm) {
	ctx := r.Context()
	ip := clientIP(r)
	for _, v := range []struct{ val, name string }{{in.clientID, "client_id"}, {in.scope, "scope"}, {in.webauthnToken, "token"}, {in.deviceResponse, "deviceResponse"},
		{in.deviceID, "device_identifier"}, {in.deviceName, "device_name"}, {in.deviceType, "device_type"}} {
		if v.val == "" {
			bwErr(w, http.StatusBadRequest, v.name+" cannot be blank")
			return
		}
	}
	if in.scope != "api offline_access" {
		bwErr(w, http.StatusBadRequest, "Scope ("+in.scope+") not supported")
		return
	}
	if s.tooManyTries(ip) {
		bwErr(w, http.StatusTooManyRequests, "Too many tries. Wait ten minutes and try again.")
		return
	}
	claims, ok := s.readPasskeyToken(in.webauthnToken, "passkey-login", "")
	if !ok {
		bwErr(w, http.StatusBadRequest, "That took too long or was already used. Try again.")
		return
	}
	wa, err := s.webAuthn(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(in.deviceResponse))
	if err != nil {
		bwErr(w, http.StatusBadRequest, "The passkey's answer couldn't be read.")
		return
	}
	var pk *store.Passkey
	var acct *store.VaultAccount
	find := func(rawID, userHandle []byte) (webauthn.User, error) {
		p, err := s.store.GetPasskeyByCredential(ctx, base64.RawURLEncoding.EncodeToString(rawID))
		if err != nil {
			return nil, err
		}
		a, err := s.store.GetVaultAccount(ctx, p.UserID)
		if err != nil {
			return nil, err
		}
		if len(userHandle) > 0 && string(userHandle) != a.UUID {
			return nil, errors.New("user handle")
		}
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(p.Credential), &c); err != nil {
			return nil, err
		}
		pk, acct = p, a
		return &passkeyUser{acct: a, creds: []webauthn.Credential{c}}, nil
	}
	cred, err := wa.ValidateDiscoverableLogin(find, claims.Session, parsed)
	if err != nil || cred.Authenticator.CloneWarning {
		time.Sleep(300 * time.Millisecond)
		if pk == nil {
			acct = nil
		}
		s.noteFailure(ctx, ip, acct, "signin_failed", in.deviceName)
		if pk == nil {
			bwErr(w, http.StatusBadRequest, "This passkey isn't on any vault here. Sign in with your master password and add it under Security.")
			return
		}
		bwErr(w, http.StatusBadRequest, "The passkey couldn't be checked. Try again.")
		return
	}
	if !acct.Enabled {
		bwErr(w, http.StatusBadRequest, "This vault has been switched off.")
		return
	}
	raw, _ := json.Marshal(cred)
	now := store.BWNow()
	pk.Credential, pk.LastUsedAt = string(raw), &now
	if err := s.store.SavePasskey(ctx, pk); err != nil {
		s.fail(w, err, "save passkey")
		return
	}
	if in.pocketSession && !s.pocketSessionFromPasskey(w, r, acct) {
		return
	}
	prf := map[string]any{}
	if pk.Unlocks() {
		prf = map[string]any{"EncryptedPrivateKey": pk.EncryptedPrivateKey, "EncryptedUserKey": pk.EncryptedUserKey,
			"CredentialId": pk.CredentialID, "Transports": cred.Transport}
	}
	dev, isNew := s.loginDevice(ctx, acct, in, ip)
	s.finishLogin(w, r, acct, dev, isNew, in, "", prf)
}

// pocketSessionFromPasskey signs the browser in to Pocket Vault itself, for
// our web vault's "Sign in with a passkey" (one tap: signed in and
// unlocked). Only when this app keeps its own accounts, and only from its
// own pages.
func (s *Server) pocketSessionFromPasskey(w http.ResponseWriter, r *http.Request, acct *store.VaultAccount) bool {
	if s.cfg.AuthMode != "local" {
		return true
	}
	if u, err := url.Parse(s.bwBase(r)); err != nil || r.Header.Get("Origin") != u.Scheme+"://"+u.Host {
		bwErr(w, http.StatusForbidden, "Signing in to Pocket Vault with a passkey works from its own page.")
		return false
	}
	id, err := s.store.CreateSession(r.Context(), acct.UserID, s.cfg.SessionTTL)
	if err != nil {
		s.fail(w, err, "create session")
		return false
	}
	s.setSessionCookie(w, id, s.cfg.SessionTTL)
	return true
}
