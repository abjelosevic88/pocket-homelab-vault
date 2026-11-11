package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// Two-step login types (Bitwarden's TwoFactorProviderType).
const (
	tfAuthenticator = 0
	tfRemember      = 5
	tfRecoveryCode  = 8
)

// ---- /identity ----

// handlePrelogin tells an app how to turn the master password into a key.
// Unknown emails get the defaults, so nobody can find out who has a vault.
func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	in, err := readBWJSON(r)
	if err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	kdf, iter := 0, 600000
	var mem, par *int
	if a, err := s.store.GetVaultAccountByEmail(r.Context(), jStr(in, "email")); err == nil {
		kdf, iter, mem, par = a.KdfType, a.KdfIterations, a.KdfMemory, a.KdfParallelism
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"kdf": kdf, "kdfIterations": iter, "kdfMemory": kdfNum(mem), "kdfParallelism": kdfNum(par),
		"kdfSettings": map[string]any{"iterations": iter, "kdfType": kdf, "memory": kdfNum(mem), "parallelism": kdfNum(par)},
		"salt":        nil,
	})
}

// handleRegister refuses: a vault is created in Pocket Vault itself, where
// the person is already signed in.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	bwErr(w, http.StatusBadRequest, "New vaults are created in Pocket Vault: open "+s.bwBase(r)+", sign in and choose Create your vault.")
}

// handleToken is the sign-in: password (with two-step login) or refresh.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		bwErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	f := func(names ...string) string {
		for _, n := range names {
			if v := r.PostForm.Get(n); v != "" {
				return v
			}
		}
		return ""
	}
	switch f("grant_type", "granttype") {
	case "refresh_token":
		s.refreshLogin(w, r, f("refresh_token", "refreshtoken"), f("client_id", "clientid"))
	case "password":
		s.passwordLogin(w, r, loginForm{
			clientID: f("client_id", "clientid"), password: f("password"), scope: f("scope"), username: f("username"),
			deviceID: strings.ToLower(f("deviceidentifier", "device_identifier", "deviceIdentifier")), deviceName: f("devicename", "device_name", "deviceName"),
			deviceType: f("devicetype", "device_type", "deviceType"), provider: f("twofactorprovider", "two_factor_provider", "twoFactorProvider"),
			token: f("twofactortoken", "two_factor_token", "twoFactorToken"), remember: f("twofactorremember", "two_factor_remember", "twoFactorRemember"),
			authRequest: f("authrequest", "authRequest"),
		})
	case "webauthn":
		s.passkeyLogin(w, r, loginForm{
			clientID: f("client_id", "clientid"), scope: f("scope"),
			deviceID: strings.ToLower(f("deviceidentifier", "device_identifier", "deviceIdentifier")), deviceName: f("devicename", "device_name", "deviceName"),
			deviceType: f("devicetype", "device_type", "deviceType"), webauthnToken: f("token"), deviceResponse: f("deviceresponse", "deviceResponse", "device_response"),
			pocketSession: f("pocket_session") == "1",
		})
	case "client_credentials":
		bwErr(w, http.StatusBadRequest, "Signing in with an API key isn't available; sign in with your email and master password.")
	case "authorization_code":
		bwErr(w, http.StatusBadRequest, "Single sign-on isn't available here; sign in with your email and master password.")
	default:
		bwErr(w, http.StatusBadRequest, "Invalid type")
	}
}

type loginForm struct {
	clientID, password, scope, username, deviceID, deviceName, deviceType, provider, token, remember, authRequest string
	webauthnToken, deviceResponse                                                                                 string
	pocketSession                                                                                                 bool // our web vault: sign in to Pocket Vault too
}

func (s *Server) refreshLogin(w http.ResponseWriter, r *http.Request, tok, clientID string) {
	bad := func() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "invalid_grant", "message": "Your session has ended. Sign in again.", "object": "error"})
	}
	var c bw.RefreshClaims
	if tok == "" || bw.Verify(&s.bwKey().PublicKey, tok, s.bw.issuer, &c) != nil || c.Sub != "password" {
		bad()
		return
	}
	ctx := r.Context()
	dev, err := s.store.GetDeviceByRefreshToken(ctx, c.DeviceToken)
	if err != nil {
		bad()
		return
	}
	acct, err := s.store.GetVaultAccount(ctx, dev.UserID)
	if err != nil || !acct.Enabled {
		bad()
		return
	}
	dev.LastIP = clientIP(r)
	if err := s.store.SaveDevice(ctx, dev, true); err != nil {
		s.fail(w, err, "save device")
		return
	}
	access, refresh, exp, err := s.issueTokens(acct, dev, clientID)
	if err != nil {
		s.fail(w, err, "token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"refresh_token": refresh, "access_token": access, "expires_in": exp, "token_type": "Bearer", "scope": "api offline_access"})
}

func (s *Server) passwordLogin(w http.ResponseWriter, r *http.Request, in loginForm) {
	ctx := r.Context()
	ip := clientIP(r)
	for _, v := range []struct{ val, name string }{{in.clientID, "client_id"}, {in.password, "password"}, {in.scope, "scope"}, {in.username, "username"},
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
	if in.authRequest != "" {
		bwErr(w, http.StatusBadRequest, "Signing in with another device isn't available; use your master password.")
		return
	}
	acct, err := s.store.GetVaultAccountByEmail(ctx, in.username)
	if err != nil || !bw.CheckMaster(in.password, acct.MasterSalt, acct.MasterHash, acct.MasterIterations) {
		time.Sleep(300 * time.Millisecond)
		if err != nil {
			acct = nil
		}
		s.noteFailure(ctx, ip, acct, "signin_failed", in.deviceName)
		bwErr(w, http.StatusBadRequest, "Username or password is incorrect. Try again")
		return
	}
	if !acct.Enabled {
		bwErr(w, http.StatusBadRequest, "This vault has been switched off.")
		return
	}
	dev, isNew := s.loginDevice(ctx, acct, in, ip)
	rememberTok, ok := s.twoFactorStep(w, r, acct, dev, in, ip)
	if !ok {
		return
	}
	s.finishLogin(w, r, acct, dev, isNew, in, rememberTok, nil)
}

// loginDevice is the app signing in: known already, or new.
func (s *Server) loginDevice(ctx context.Context, acct *store.VaultAccount, in loginForm, ip string) (*store.Device, bool) {
	dtype := 14
	if n, err := strconv.Atoi(in.deviceType); err == nil {
		dtype = n
	} else if strings.EqualFold(in.deviceType, "ios") {
		dtype = 1
	}
	dev, err := s.store.GetDevice(ctx, acct.UserID, in.deviceID)
	isNew := false
	if err != nil {
		isNew = true
		dev = &store.Device{UserID: acct.UserID, UUID: in.deviceID, Name: in.deviceName, Type: dtype, RefreshToken: store.RandomToken(48)}
	}
	dev.Name, dev.Type, dev.LastIP, dev.ClientID = in.deviceName, dtype, ip, in.clientID
	return dev, isNew
}

// finishLogin saves the device, issues the tokens and answers with what the
// app needs to unlock (prf: the keys a passkey opens, when it signed in with one).
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, acct *store.VaultAccount, dev *store.Device, isNew bool, in loginForm, rememberTok string, prf map[string]any) {
	ctx := r.Context()
	ip := clientIP(r)
	dev.LastIP = ip
	dtype := dev.Type
	if err := s.store.SaveDevice(ctx, dev, true); err != nil {
		s.fail(w, err, "save device")
		return
	}
	access, refresh, exp, err := s.issueTokens(acct, dev, in.clientID)
	if err != nil {
		s.fail(w, err, "token")
		return
	}
	s.clearFailures(acct.UserID)
	dt := dtype
	detail := ""
	if prf != nil {
		detail = "with a passkey"
	}
	if isNew {
		s.store.AddVaultEvent(ctx, acct.UserID, store.VaultEvent{Kind: "new_device", DeviceName: in.deviceName, DeviceType: &dt, IP: ip, Detail: detail})
		s.securityAlert(ctx, acct.UserID, "new_device", "New sign-in to your vault",
			deviceTypeName(dtype)+" ("+in.deviceName+") signed in to your vault from "+ip+". If that wasn't you, change your master password.", "info")
		s.publish(ctx, acct.UserID, "vault.device_signed_in", dev.UUID, map[string]any{"device": in.deviceName, "device_type": deviceTypeName(dtype), "ip": ip})
	} else {
		s.store.AddVaultEvent(ctx, acct.UserID, store.VaultEvent{Kind: "signed_in", DeviceName: in.deviceName, DeviceType: &dt, IP: ip, Detail: detail})
	}
	var keys any
	if acct.PrivateKey != "" {
		keys = map[string]any{"publicKeyEncryptionKeyPair": map[string]any{"wrappedPrivateKey": acct.PrivateKey, "publicKey": acct.PublicKey, "Object": "publicKeyEncryptionKeyPair"}, "Object": "privateKeys"}
	}
	opts := map[string]any{
		"HasMasterPassword": true,
		"MasterPasswordUnlock": map[string]any{
			"Kdf":                       map[string]any{"KdfType": acct.KdfType, "Iterations": acct.KdfIterations, "Memory": kdfNum(acct.KdfMemory), "Parallelism": kdfNum(acct.KdfParallelism)},
			"MasterKeyEncryptedUserKey": acct.AKey, "MasterKeyWrappedUserKey": acct.AKey, "Salt": acct.Email,
		},
		"Object": "userDecryptionOptions",
	}
	if len(prf) > 0 {
		opts["WebAuthnPrfOption"] = prf
	}
	res := map[string]any{
		"access_token": access, "expires_in": exp, "token_type": "Bearer", "refresh_token": refresh,
		"PrivateKey": nilIfEmpty(acct.PrivateKey), "Kdf": acct.KdfType, "KdfIterations": acct.KdfIterations, "KdfMemory": kdfNum(acct.KdfMemory), "KdfParallelism": kdfNum(acct.KdfParallelism),
		"ResetMasterPassword": false, "ForcePasswordReset": false, "MasterPasswordPolicy": map[string]any{"Object": "masterPasswordPolicy"},
		"scope": "api offline_access", "AccountKeys": keys, "unofficialServer": true,
		"UserDecryptionOptions": opts,
	}
	if acct.AKey != "" {
		res["Key"] = acct.AKey
	}
	if rememberTok != "" {
		res["TwoFactorToken"] = rememberTok
	}
	writeJSON(w, http.StatusOK, res)
}

// twoFactorStep asks for (or checks) the second step when the vault has
// one. ok=false means an answer was already written.
func (s *Server) twoFactorStep(w http.ResponseWriter, r *http.Request, acct *store.VaultAccount, dev *store.Device, in loginForm, ip string) (remember string, ok bool) {
	ctx := r.Context()
	tfs, err := s.store.ListTwoFactor(ctx, acct.UserID)
	if err != nil {
		s.fail(w, err, "two-step login")
		return "", false
	}
	var totp *store.TwoFactor
	providers := []int{}
	for i := range tfs {
		if tfs[i].Enabled && tfs[i].Type == tfAuthenticator {
			totp = &tfs[i]
			providers = append(providers, tfAuthenticator)
		}
	}
	if totp == nil {
		return "", true
	}
	ask := func(msg string) {
		p2 := map[string]any{}
		ps := []string{}
		for _, p := range providers {
			p2[strconv.Itoa(p)] = nil
			ps = append(ps, strconv.Itoa(p))
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_grant", "error_description": "Two factor required.", "TwoFactorProviders": ps, "TwoFactorProviders2": p2,
			"MasterPasswordPolicy": map[string]any{"Object": "masterPasswordPolicy"}, "message": msg,
		})
	}
	provider := tfAuthenticator
	if in.provider != "" {
		if n, err := strconv.Atoi(in.provider); err == nil {
			provider = n
		}
	}
	if in.token == "" {
		ask("Two factor required.")
		return "", false
	}
	switch provider {
	case tfAuthenticator:
		step, good := bw.CheckTOTP(totp.Data, in.token, totp.LastUsed, time.Now())
		if !good {
			s.noteFailure(ctx, ip, acct, "twofactor_failed", in.deviceName)
			bwErr(w, http.StatusBadRequest, "Invalid TOTP code! Server time: "+time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
			return "", false
		}
		totp.LastUsed = step
		if err := s.store.SaveTwoFactor(ctx, totp); err != nil {
			s.fail(w, err, "two-step login")
			return "", false
		}
	case tfRemember:
		var c bw.RememberClaims
		if dev.TwoFactorRemember == "" || dev.TwoFactorRemember != in.token || bw.Verify(&s.bwKey().PublicKey, in.token, s.bw.issuer, &c) != nil ||
			c.Sub != dev.UUID || c.UserUUID != acct.UUID {
			dev.TwoFactorRemember = ""
			if dev.CreatedAt != "" {
				_ = s.store.SaveDevice(ctx, dev, false)
			}
			ask("2FA Remember token not provided or expired")
			return "", false
		}
		return "", true
	case tfRecoveryCode:
		if acct.TotpRecover == "" || !strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(in.token), " ", ""), acct.TotpRecover) {
			s.noteFailure(ctx, ip, acct, "twofactor_failed", in.deviceName)
			bwErr(w, http.StatusBadRequest, "Recovery code is incorrect. Try again.")
			return "", false
		}
		_ = s.store.DeleteTwoFactor(ctx, acct.UserID, -1)
		acct.TotpRecover = ""
		_ = s.store.SaveVaultAccount(ctx, acct)
		s.store.AddVaultEvent(ctx, acct.UserID, store.VaultEvent{Kind: "twofactor_off", DeviceName: in.deviceName, IP: ip, Detail: "recovery code used"})
		s.securityAlert(ctx, acct.UserID, "security", "Two-step login turned off", "Your recovery code was used to sign in, which turned two-step login off. Turn it on again in Pocket Vault → Security.", "warning")
	default:
		ask("Invalid two factor provider")
		return "", false
	}
	if in.remember == "1" {
		now := time.Now()
		tok, err := bw.Sign(s.bwKey(), bw.RememberClaims{Nbf: now.Unix(), Exp: now.Add(rememberFor).Unix(), Iss: s.bw.issuer, Sub: dev.UUID, UserUUID: acct.UUID})
		if err == nil {
			dev.TwoFactorRemember = tok
			remember = tok
		}
	}
	return remember, true
}

// handleKnownDevice answers whether this app already signed in to the
// vault (apps then skip the new-device check).
func (s *Server) handleKnownDevice(w http.ResponseWriter, r *http.Request) {
	email := r.Header.Get("X-Request-Email")
	dev := r.Header.Get("X-Device-Identifier")
	if e := chiParam(r, "email"); e != "" {
		email, dev = e, chiParam(r, "uuid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(email, "="))
	if err != nil {
		bwErr(w, http.StatusBadRequest, "X-Request-Email value failed to decode as base64url")
		return
	}
	known := false
	if a, err := s.store.GetVaultAccountByEmail(r.Context(), string(raw)); err == nil {
		_, err := s.store.GetDevice(r.Context(), a.UserID, strings.ToLower(dev))
		known = err == nil
	}
	writeJSON(w, http.StatusOK, known)
}

// checkSecret verifies the master password hash an app sends with a
// sensitive request (or, for two-step settings, a one-time code).
func (s *Server) checkSecret(ctx context.Context, a *store.VaultAccount, in map[string]any) bool {
	if h := jStr(in, "masterPasswordHash"); h != "" {
		return bw.CheckMaster(h, a.MasterSalt, a.MasterHash, a.MasterIterations)
	}
	return false
}
