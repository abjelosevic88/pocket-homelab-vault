package server

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// ---- the Bitwarden-compatible server: shared pieces ----
//
// The Bitwarden apps (browser extension, phone, desktop, CLI) and this
// app's own web vault talk to /identity, /api and /notifications exactly as
// they talk to bitwarden.com or Vaultwarden. They encrypt everything on the
// device; the server stores the encrypted text and the bookkeeping around it.

// bwState is the server's Bitwarden side.
type bwState struct {
	key    atomic.Pointer[rsa.PrivateKey]
	issuer string
	hub    *hub

	limitMu sync.Mutex
	tries   map[string][]time.Time // failed sign-ins per address
	failed  map[int64]failCount    // failed sign-ins per vault, for the alert
}

type failCount struct {
	n        int
	alerted  time.Time
	lastFail time.Time
}

// loadBW reads (or makes) the token signing key. Keeping Vaultwarden's
// rsa_key.pem here keeps every app signed in after a move.
func (s *Server) loadBW() error {
	k, err := bw.LoadOrCreateKey(s.cfg.DataDir + "/rsa_key.pem")
	if err != nil {
		return err
	}
	s.bw = &bwState{issuer: s.bwOrigin() + "|login", hub: newHub(), tries: map[string][]time.Time{}, failed: map[int64]failCount{}}
	s.bw.key.Store(k)
	return nil
}

// bwKey is the token signing key (swapped when Vaultwarden's is imported).
func (s *Server) bwKey() *rsa.PrivateKey { return s.bw.key.Load() }

func (s *Server) setBWKey(k *rsa.PrivateKey) { s.bw.key.Store(k) }

// bwOrigin is scheme://host[:port] of BASE_URL (Vaultwarden's "domain origin").
func (s *Server) bwOrigin() string {
	if u, err := url.Parse(s.cfg.BaseURL); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "http://localhost:" + strconv.Itoa(s.cfg.Port)
}

// bwBase is the public address apps use ("https://vault.example.com").
func (s *Server) bwBase(r *http.Request) string {
	if s.cfg.BaseURL != "" {
		return s.cfg.BaseURL
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// ---- errors in the shape the apps show ----

// bwErr answers with Bitwarden's error model; the apps show message.
func bwErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"message":               msg,
		"validationErrors":      map[string][]string{"": {msg}},
		"errorModel":            map[string]any{"message": msg, "object": "error"},
		"error":                 "",
		"error_description":     "",
		"exceptionMessage":      nil,
		"exceptionStackTrace":   nil,
		"innerExceptionMessage": nil,
		"object":                "error",
	})
}

// bwList is Bitwarden's list envelope.
func bwList(data any) map[string]any {
	return map[string]any{"data": data, "object": "list", "continuationToken": nil}
}

// ---- the signed-in app on a request ----

type bwKey int

const bwCtxKey bwKey = 1

// bwSession is who is calling: the vault, its Pocket user and the device.
type bwSession struct {
	acct   *store.VaultAccount
	device *store.Device
	claims *bw.LoginClaims
}

func bwFrom(ctx context.Context) *bwSession {
	b, _ := ctx.Value(bwCtxKey).(*bwSession)
	return b
}

// bwAuth checks the access token an app sends (Authorization: Bearer …):
// the signature, the account, the device it was issued to and the account's
// security stamp (a master password change signs every app out).
func (s *Server) bwAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		tok := ""
		if strings.HasPrefix(h, "Bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
		sess, err := s.bwSessionFor(r.Context(), tok)
		if err != nil {
			bwErr(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), bwCtxKey, sess)))
	})
}

func (s *Server) bwSessionFor(ctx context.Context, tok string) (*bwSession, error) {
	if tok == "" {
		return nil, bw.ErrToken
	}
	var c bw.LoginClaims
	if err := bw.Verify(&s.bwKey().PublicKey, tok, s.bw.issuer, &c); err != nil {
		return nil, err
	}
	acct, err := s.store.GetVaultAccountByUUID(ctx, c.Sub)
	if err != nil || !acct.Enabled {
		return nil, bw.ErrToken
	}
	dev, err := s.store.GetDevice(ctx, acct.UserID, c.Device)
	if err != nil {
		return nil, bw.ErrToken
	}
	if c.SStamp != acct.SecurityStamp {
		return nil, bw.ErrToken
	}
	return &bwSession{acct: acct, device: dev, claims: &c}, nil
}

// ---- tokens ----

const (
	refreshDesktop = 30 * 24 * time.Hour
	refreshMobile  = 90 * 24 * time.Hour
	rememberFor    = 30 * 24 * time.Hour
)

var deviceTypeNames = map[int]string{0: "Android", 1: "iOS", 2: "Chrome Extension", 3: "Firefox Extension", 4: "Opera Extension", 5: "Edge Extension",
	6: "Windows", 7: "macOS", 8: "Linux", 9: "Chrome", 10: "Firefox", 11: "Opera", 12: "Edge", 13: "Internet Explorer", 14: "Unknown Browser",
	15: "Android", 16: "UWP", 17: "Safari", 18: "Vivaldi", 19: "Vivaldi Extension", 20: "Safari Extension", 21: "SDK", 22: "Server",
	23: "Windows CLI", 24: "macOS CLI", 25: "Linux CLI", 26: "DuckDuckGo"}

func deviceTypeName(t int) string {
	if n, ok := deviceTypeNames[t]; ok {
		return n
	}
	return "Unknown Browser"
}

func isMobile(t int) bool { return t == 0 || t == 1 || t == 15 }

// issueTokens makes an access token and a refresh token for a device.
func (s *Server) issueTokens(a *store.VaultAccount, d *store.Device, clientID string) (access, refresh string, expiresIn int64, err error) {
	now := time.Now()
	if clientID == "" {
		clientID = "undefined"
	}
	exp := now.Add(s.cfg.AccessTTL)
	access, err = bw.Sign(s.bwKey(), bw.LoginClaims{
		Nbf: now.Unix(), Exp: exp.Unix(), Iss: s.bw.issuer, Sub: a.UUID, Premium: true, Name: a.Name, Email: a.Email, EmailVerified: true,
		SStamp: a.SecurityStamp, Device: d.UUID, DeviceType: deviceTypeName(d.Type), ClientID: clientID,
		Scope: []string{"api", "offline_access"}, Amr: []string{"Application"},
	})
	if err != nil {
		return
	}
	valid := refreshDesktop
	if isMobile(d.Type) {
		valid = refreshMobile
	}
	refresh, err = bw.Sign(s.bwKey(), bw.RefreshClaims{Nbf: now.Unix(), Exp: now.Add(valid).Unix(), Iss: s.bw.issuer, Sub: "password", DeviceToken: d.RefreshToken, Token: json.RawMessage("null")})
	return access, refresh, int64(s.cfg.AccessTTL.Seconds()), err
}

// ---- sign-in limits ----

// tooManyTries reports whether an address failed too often in 10 minutes.
func (s *Server) tooManyTries(ip string) bool {
	if s.cfg.LoginAttempts <= 0 {
		return false
	}
	s.bw.limitMu.Lock()
	defer s.bw.limitMu.Unlock()
	cut := time.Now().Add(-10 * time.Minute)
	keep := s.bw.tries[ip][:0]
	for _, t := range s.bw.tries[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.bw.tries[ip] = keep
	return len(keep) >= s.cfg.LoginAttempts
}

// noteFailure counts a failed try for the address and (when known) the
// vault; the third failure in a row raises an alert, at most once an hour.
func (s *Server) noteFailure(ctx context.Context, ip string, acct *store.VaultAccount, kind, device string) {
	s.bw.limitMu.Lock()
	s.bw.tries[ip] = append(s.bw.tries[ip], time.Now())
	alert := false
	n := 0
	if acct != nil {
		f := s.bw.failed[acct.UserID]
		if time.Since(f.lastFail) > time.Hour {
			f.n = 0
		}
		f.n++
		f.lastFail = time.Now()
		n = f.n
		if f.n >= 3 && time.Since(f.alerted) > time.Hour {
			f.alerted = time.Now()
			alert = true
		}
		s.bw.failed[acct.UserID] = f
	}
	s.bw.limitMu.Unlock()
	if acct == nil {
		return
	}
	s.store.AddVaultEvent(ctx, acct.UserID, store.VaultEvent{Kind: kind, DeviceName: device, IP: ip})
	if alert {
		s.securityAlert(ctx, acct.UserID, "failed", "Several wrong tries on your vault",
			strconv.Itoa(n)+" wrong master passwords or codes in a row (last from "+ip+"). If that wasn't you, change your master password and turn on two-step login.", "warning")
		s.publish(ctx, acct.UserID, "vault.signin_failed", acct.UUID, map[string]any{"tries": n, "ip": ip})
	}
}

func (s *Server) clearFailures(uid int64) {
	s.bw.limitMu.Lock()
	delete(s.bw.failed, uid)
	s.bw.limitMu.Unlock()
}

// clientIP is the caller's address (RealIP has already applied X-Forwarded-For).
func clientIP(r *http.Request) string {
	h := r.RemoteAddr
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.Trim(h, "[]")
}

// ---- reading what the apps send ----

// lowerFirst turns "FolderId" into "folderId" all the way down, so older
// apps (PascalCase) and newer ones (camelCase) read the same.
func lowerFirst(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if k != "" {
				k = strings.ToLower(k[:1]) + k[1:]
			}
			out[k] = lowerFirst(e)
		}
		return out
	case []any:
		for i := range x {
			x[i] = lowerFirst(x[i])
		}
		return x
	}
	return v
}

// readBWJSON decodes a request body into a camelCase map.
func readBWJSON(r *http.Request) (map[string]any, error) {
	var raw any
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<20))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	m, _ := lowerFirst(raw).(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func jStr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return ""
}

func jStrPtr(m map[string]any, k string) *string {
	if v, ok := m[k].(string); ok {
		return &v
	}
	return nil
}

func jInt(m map[string]any, k string, def int) int {
	switch v := m[k].(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	case float64:
		return int(v)
	}
	return def
}

func jIntPtr(m map[string]any, k string) *int {
	if _, ok := m[k]; !ok || m[k] == nil {
		return nil
	}
	v := jInt(m, k, 0)
	return &v
}

func jBool(m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

func jMap(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	return v
}

func jList(m map[string]any, k string) []any {
	v, _ := m[k].([]any)
	return v
}

func jStrings(m map[string]any, k string) []string {
	var out []string
	for _, v := range jList(m, k) {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, strings.ToLower(s))
		}
	}
	return out
}

// jsonText marshals v (nil stays nil).
func jsonText(v any) *string {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	s := string(b)
	return &s
}

// ---- the account as the apps see it ----

// bwProfile is the "profile" object of a sync.
func (s *Server) bwProfile(ctx context.Context, a *store.VaultAccount) map[string]any {
	tfs, _ := s.store.ListTwoFactor(ctx, a.UserID)
	tfOn := false
	for _, t := range tfs {
		if t.Enabled && t.Type == 0 {
			tfOn = true
		}
	}
	var keys any
	if a.PrivateKey != "" {
		keys = map[string]any{
			"publicKeyEncryptionKeyPair": map[string]any{"wrappedPrivateKey": a.PrivateKey, "publicKey": a.PublicKey, "signedPublicKey": nil, "object": "publicKeyEncryptionKeyPair"},
			"securityState":              nil, "signatureKeyPair": nil, "object": "privateKeys",
		}
	}
	status := 0
	if len(a.MasterHash) == 0 {
		status = 1
	}
	return map[string]any{
		"_status": status, "accountKeys": keys, "id": a.UUID, "name": a.Name, "email": a.Email, "emailVerified": true,
		"premium": true, "premiumFromOrganization": false, "culture": "en-US", "twoFactorEnabled": tfOn,
		"key": a.AKey, "privateKey": nilIfEmpty(a.PrivateKey), "securityStamp": a.SecurityStamp, "organizations": []any{},
		"providers": []any{}, "providerOrganizations": []any{}, "forcePasswordReset": false, "avatarColor": a.AvatarColor,
		"usesKeyConnector": false, "creationDate": store.BWDate(a.CreatedAt), "object": "profile",
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func kdfNum(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// bwFolder is a folder as the apps see it.
func bwFolder(f store.Folder) map[string]any {
	return map[string]any{"id": f.UUID, "revisionDate": store.BWDate(f.UpdatedAt), "name": f.Name, "object": "folder"}
}

// bwDevice is a device as the apps see it.
func bwDevice(d store.Device) map[string]any {
	return map[string]any{"id": d.UUID, "name": d.Name, "type": d.Type, "identifier": d.UUID, "creationDate": store.BWDate(d.CreatedAt),
		"revisionDate": store.BWDate(d.UpdatedAt), "devicePendingAuthRequest": nil, "isTrusted": false, "encryptedPublicKey": nil, "encryptedUserKey": nil, "object": "device"}
}

var cipherTypeKeys = map[int]string{1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey", 6: "bankAccount", 7: "driversLicense", 8: "passport"}

// bwCipher is an item as the apps see it ("cipherDetails").
func bwCipher(c store.Cipher) map[string]any {
	var fields []any
	if c.Fields != nil {
		var raw []any
		if json.Unmarshal([]byte(*c.Fields), &raw) == nil {
			for _, f := range raw {
				fm, ok := lowerFirst(f).(map[string]any)
				if !ok {
					continue
				}
				switch t := fm["type"].(type) {
				case float64:
				case string:
					n, err := strconv.Atoi(t)
					if err != nil {
						n = 1
					}
					fm["type"] = n
				default:
					fm["type"] = 1 // hidden, so nothing is shown by mistake
				}
				fields = append(fields, fm)
			}
		}
	}
	if fields == nil {
		fields = []any{}
	}
	hist := []any{}
	if c.PasswordHistory != nil {
		var raw []any
		if json.Unmarshal([]byte(*c.PasswordHistory), &raw) == nil {
			for _, h := range raw {
				hm, ok := lowerFirst(h).(map[string]any)
				if !ok {
					continue
				}
				if _, ok := hm["password"].(string); !ok {
					continue
				}
				lud, _ := hm["lastUsedDate"].(string)
				if d := fixDate(lud); d != "" {
					hm["lastUsedDate"] = d
				} else {
					hm["lastUsedDate"] = "1970-01-01T00:00:00.000000Z"
				}
				hist = append(hist, hm)
			}
		}
	}
	var data any = map[string]any{}
	var dm map[string]any
	if json.Unmarshal([]byte(c.Data), &data) == nil {
		dm, _ = lowerFirst(data).(map[string]any)
	}
	if dm == nil {
		dm = map[string]any{}
	}
	switch c.Type {
	case 1:
		dm["uri"] = nil
		if uris, ok := dm["uris"].([]any); ok && len(uris) > 0 {
			for _, u := range uris {
				if um, ok := u.(map[string]any); ok {
					if ms, ok := um["match"].(string); ok {
						if n, err := strconv.Atoi(ms); err == nil {
							um["match"] = n
						} else {
							um["match"] = nil
						}
					}
				}
			}
			if um, ok := uris[0].(map[string]any); ok {
				dm["uri"] = um["uri"]
			}
		}
		if pr, ok := dm["passwordRevisionDate"].(string); ok {
			if d := fixDate(pr); d != "" {
				dm["passwordRevisionDate"] = d
			}
		}
	case 2:
		if _, ok := dm["type"].(float64); !ok {
			dm = map[string]any{"type": 0}
		}
	}
	var typed any = dm
	if c.Type == 5 {
		if str(dm["keyFingerprint"]) == "" || str(dm["privateKey"]) == "" || str(dm["publicKey"]) == "" {
			typed = nil
		}
	}
	var deleted, archived any
	if c.DeletedAt != nil {
		deleted = store.BWDate(*c.DeletedAt)
	}
	if c.ArchivedAt != nil {
		archived = store.BWDate(*c.ArchivedAt)
	}
	reprompt := c.Reprompt
	if reprompt != 0 && reprompt != 1 {
		reprompt = 0
	}
	out := map[string]any{
		"object": "cipherDetails", "id": c.UUID, "type": c.Type, "creationDate": store.BWDate(c.CreatedAt), "revisionDate": store.BWDate(c.UpdatedAt),
		"deletedDate": deleted, "archivedDate": archived, "reprompt": reprompt, "organizationId": nil, "key": c.Key, "attachments": nil,
		"organizationUseTotp": true, "collectionIds": []any{}, "name": c.Name, "notes": c.Notes, "fields": fields, "passwordHistory": hist,
		"login": nil, "secureNote": nil, "card": nil, "identity": nil, "sshKey": nil, "bankAccount": nil, "driversLicense": nil, "passport": nil,
		"folderId": c.FolderUUID, "favorite": c.Favorite, "edit": true, "viewPassword": true,
		"permissions": map[string]any{"delete": true, "restore": true},
	}
	if k, ok := cipherTypeKeys[c.Type]; ok {
		out[k] = typed
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// fixDate re-writes a date the apps sent into the Bitwarden form ("" if bad).
func fixDate(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return ""
	}
	return t.UTC().Format(store.BWTime)
}
