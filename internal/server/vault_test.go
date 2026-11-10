package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// vaultEnv is a running server with two people, each with a vault:
// Alice (admin) and Bob (member).
type vaultEnv struct {
	t     *testing.T
	s     *Server
	ts    *httptest.Server
	alice *person
	bob   *person
}

type person struct {
	user     *store.User
	email    string
	password string
	key      bw.SymKey // the user key, as an app holds it after unlocking
	hash     string
}

func newVaultEnv(t *testing.T) *vaultEnv {
	t.Helper()
	cfg := testConfig(t.TempDir())
	cfg.AccessTTL, cfg.LoginAttempts, cfg.Port = time.Hour, 50, 8080
	st := openTestStore(t, cfg)
	ts := httptest.NewUnstartedServer(nil)
	cfg.BaseURL = "http://" + ts.Listener.Addr().String()
	s := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := s.core.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.loadBW(); err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s.Router()
	ts.Start()
	t.Cleanup(ts.Close)
	e := &vaultEnv{t: t, s: s, ts: ts}
	e.alice = e.makePerson("alice@example.com", "admin", "alice master password")
	e.bob = e.makePerson("bob@example.com", "member", "bob master password")
	return e
}

func (e *vaultEnv) makePerson(email, role, password string) *person {
	ctx := context.Background()
	u := &store.User{Email: email, Name: strings.Split(email, "@")[0], Role: role}
	if err := e.s.store.CreateUser(ctx, u); err != nil {
		e.t.Fatal(err)
	}
	hash, uk, protected, pub, priv, err := bw.NewAccountKeys(password, email, 100000)
	if err != nil {
		e.t.Fatal(err)
	}
	salt := bw.RandomBytes(64)
	a := &store.VaultAccount{UserID: u.ID, UUID: uuid.NewString(), Email: email, Name: u.Name, MasterSalt: salt, MasterIterations: 1000,
		MasterHash: bw.HashMaster(hash, salt, 1000), AKey: protected, PublicKey: pub, PrivateKey: priv, SecurityStamp: uuid.NewString(),
		KdfIterations: 100000, Enabled: true}
	if err := e.s.store.CreateVaultAccount(ctx, a); err != nil {
		e.t.Fatal(err)
	}
	return &person{user: u, email: email, password: password, key: uk, hash: hash}
}

type tokenRes struct {
	status  int
	access  string
	refresh string
	body    map[string]any
}

func (e *vaultEnv) login(p *person, device string, extra url.Values) tokenRes {
	f := url.Values{"grant_type": {"password"}, "username": {p.email}, "password": {p.hash}, "scope": {"api offline_access"}, "client_id": {"browser"},
		"deviceType": {"2"}, "deviceIdentifier": {device}, "deviceName": {"chrome"}}
	for k, v := range extra {
		f[k] = v
	}
	return e.token(f)
}

func (e *vaultEnv) token(f url.Values) tokenRes {
	res, err := http.PostForm(e.ts.URL+"/identity/connect/token", f)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	a, _ := body["access_token"].(string)
	r, _ := body["refresh_token"].(string)
	return tokenRes{res.StatusCode, a, r, body}
}

func (e *vaultEnv) call(method, path, tok string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out
}

func (p *person) login(name, user, pass string) map[string]any {
	return map[string]any{"type": 1, "name": p.key.EncryptString(name), "notes": nil, "favorite": false, "reprompt": 0,
		"login": map[string]any{"username": p.key.EncryptString(user), "password": p.key.EncryptString(pass),
			"uris":             []any{map[string]any{"uri": p.key.EncryptString("https://example.org"), "match": nil, "response": "drop me"}},
			"fido2Credentials": []any{map[string]any{"credentialId": p.key.EncryptString("cred"), "keyType": p.key.EncryptString("public-key")}}}}
}

func TestBitwardenSignInSyncAndItems(t *testing.T) {
	e := newVaultEnv(t)
	tr := e.login(e.alice, "11111111-1111-1111-1111-111111111111", nil)
	if tr.status != 200 || tr.access == "" || tr.refresh == "" {
		t.Fatalf("login: %d %v", tr.status, tr.body)
	}
	// the app unlocks with what the server returns
	k, err := bw.Stretch(bw.MasterKey(e.alice.password, e.alice.email, 100000)).Decrypt(tr.body["Key"].(string))
	if err != nil || string(k) != string(e.alice.key.Bytes()) {
		t.Fatalf("user key does not unlock: %v", err)
	}
	// wrong password
	bad := e.alice
	if r := e.login(&person{email: bad.email, hash: "nope"}, "x", nil); r.status != 400 {
		t.Fatalf("wrong password: %d", r.status)
	}
	// create, read, update, soft delete, restore, delete
	st, c := e.call("POST", "/api/ciphers", tr.access, e.alice.login("Mail", "alice", "pw1"))
	if st != 200 {
		t.Fatalf("create: %d %v", st, c)
	}
	id := c["id"].(string)
	login := c["login"].(map[string]any)
	if _, ok := login["fido2Credentials"]; !ok {
		t.Fatal("passkeys were dropped")
	}
	if u := login["uris"].([]any)[0].(map[string]any); u["response"] != nil {
		t.Fatal("response was kept")
	}
	name, _ := e.alice.key.Decrypt(c["name"].(string))
	if string(name) != "Mail" {
		t.Fatalf("name = %q", name)
	}
	upd := e.alice.login("Mail 2", "alice", "pw2")
	upd["lastKnownRevisionDate"] = c["revisionDate"]
	if st, _ := e.call("PUT", "/api/ciphers/"+id, tr.access, upd); st != 200 {
		t.Fatalf("update: %d", st)
	}
	old := e.alice.login("stale", "alice", "pw3")
	old["lastKnownRevisionDate"] = "2020-01-01T00:00:00.000Z"
	if st, _ := e.call("PUT", "/api/ciphers/"+id, tr.access, old); st != 400 {
		t.Fatalf("stale update accepted: %d", st)
	}
	if st, _ := e.call("PUT", "/api/ciphers/"+id+"/delete", tr.access, nil); st != 200 {
		t.Fatalf("soft delete: %d", st)
	}
	_, got := e.call("GET", "/api/ciphers/"+id, tr.access, nil)
	if got["deletedDate"] == nil {
		t.Fatal("not in the bin")
	}
	if st, _ := e.call("PUT", "/api/ciphers/"+id+"/restore", tr.access, nil); st != 200 {
		t.Fatalf("restore: %d", st)
	}
	// folders
	st, f := e.call("POST", "/api/folders", tr.access, map[string]any{"name": e.alice.key.EncryptString("Work")})
	if st != 200 {
		t.Fatalf("folder: %d", st)
	}
	if st, _ := e.call("PUT", "/api/ciphers/"+id+"/partial", tr.access, map[string]any{"folderId": f["id"], "favorite": true}); st != 200 {
		t.Fatalf("partial: %d", st)
	}
	st, sync := e.call("GET", "/api/sync", tr.access, nil)
	if st != 200 || len(sync["ciphers"].([]any)) != 1 || len(sync["folders"].([]any)) != 1 {
		t.Fatalf("sync: %d %v", st, sync)
	}
	ci := sync["ciphers"].([]any)[0].(map[string]any)
	if ci["folderId"] != f["id"] || ci["favorite"] != true || ci["deletedDate"] != nil {
		t.Fatalf("sync item: %v", ci)
	}
	if prof := sync["profile"].(map[string]any); prof["email"] != e.alice.email || prof["key"] == "" {
		t.Fatalf("profile: %v", prof)
	}
	// refresh
	r2 := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.refresh}, "client_id": {"browser"}})
	if r2.status != 200 || r2.access == "" {
		t.Fatalf("refresh: %d %v", r2.status, r2.body)
	}
	if st, _ := e.call("DELETE", "/api/ciphers/"+id, r2.access, nil); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if st, _ := e.call("GET", "/api/ciphers/"+id, r2.access, nil); st != 404 {
		t.Fatalf("deleted item still there: %d", st)
	}
	if st, _ := e.call("GET", "/api/sync", "", nil); st != 401 {
		t.Fatalf("no token: %d", st)
	}
}

// One person's token never reaches another person's items or folders.
func TestVaultIsPerPerson(t *testing.T) {
	e := newVaultEnv(t)
	a := e.login(e.alice, "aaaaaaaa-0000-0000-0000-000000000001", nil)
	b := e.login(e.bob, "bbbbbbbb-0000-0000-0000-000000000001", nil)
	_, c := e.call("POST", "/api/ciphers", a.access, e.alice.login("Alice's", "alice", "secret"))
	_, f := e.call("POST", "/api/folders", a.access, map[string]any{"name": e.alice.key.EncryptString("Alice folder")})
	id, fid := c["id"].(string), f["id"].(string)
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/ciphers/" + id, nil},
		{"PUT", "/api/ciphers/" + id, e.bob.login("mine now", "bob", "x")},
		{"PUT", "/api/ciphers/" + id + "/delete", nil},
		{"DELETE", "/api/ciphers/" + id, nil},
		{"PUT", "/api/ciphers/" + id + "/partial", map[string]any{"favorite": true}},
		{"GET", "/api/folders/" + fid, nil},
		{"PUT", "/api/folders/" + fid, map[string]any{"name": e.bob.key.EncryptString("x")}},
		{"DELETE", "/api/folders/" + fid, nil},
	} {
		if st, _ := e.call(tc.method, tc.path, b.access, tc.body); st != 404 {
			t.Errorf("%s %s as Bob: %d, want 404", tc.method, tc.path, st)
		}
	}
	// Bob can't file his item into Alice's folder, nor move Alice's item
	bi := e.bob.login("Bob's", "bob", "x")
	bi["folderId"] = fid
	if st, _ := e.call("POST", "/api/ciphers", b.access, bi); st != 400 {
		t.Errorf("Bob used Alice's folder: %d", st)
	}
	e.call("POST", "/api/ciphers/delete", b.access, map[string]any{"ids": []string{id}})
	e.call("POST", "/api/ciphers/move", b.access, map[string]any{"ids": []string{id}, "folderId": nil})
	if _, got := e.call("GET", "/api/ciphers/"+id, a.access, nil); got["id"] != id || got["folderId"] != nil {
		// folderId was nil from the start; the item must still be there
		if got["id"] != id {
			t.Fatal("Bob's bulk calls touched Alice's item")
		}
	}
	_, bs := e.call("GET", "/api/sync", b.access, nil)
	if len(bs["ciphers"].([]any)) != 0 || len(bs["folders"].([]any)) != 0 {
		t.Fatal("Bob's sync shows Alice's data")
	}
	// Alice's token, Bob's device id: refused
	if st, _ := e.call("GET", "/api/devices/identifier/bbbbbbbb-0000-0000-0000-000000000001", a.access, nil); st != 404 {
		t.Errorf("Alice saw Bob's device: %d", st)
	}
}

func TestTwoStepLoginAndPasswordChange(t *testing.T) {
	e := newVaultEnv(t)
	dev := "cccccccc-0000-0000-0000-000000000001"
	tr := e.login(e.alice, dev, nil)
	st, g := e.call("POST", "/api/two-factor/get-authenticator", tr.access, map[string]any{"masterPasswordHash": e.alice.hash})
	if st != 200 {
		t.Fatalf("get-authenticator: %d", st)
	}
	key := g["key"].(string)
	code, _ := bw.TOTP(key, time.Now().Unix()/30)
	if st, _ := e.call("POST", "/api/two-factor/authenticator", tr.access, map[string]any{"key": key, "token": code, "masterPasswordHash": "wrong"}); st != 400 {
		t.Fatalf("enabled without the password: %d", st)
	}
	if st, r := e.call("POST", "/api/two-factor/authenticator", tr.access, map[string]any{"key": key, "token": code, "masterPasswordHash": e.alice.hash}); st != 200 {
		t.Fatalf("enable: %d %v", st, r)
	}
	// now a sign-in asks for the code
	r := e.login(e.alice, "cccccccc-0000-0000-0000-000000000002", nil)
	if r.status != 400 || r.body["TwoFactorProviders"] == nil {
		t.Fatalf("no second step asked: %d %v", r.status, r.body)
	}
	// the code just used can't be used again
	if r := e.login(e.alice, "cccccccc-0000-0000-0000-000000000002", url.Values{"twoFactorProvider": {"0"}, "twoFactorToken": {code}}); r.status != 400 {
		t.Fatalf("code reused: %d", r.status)
	}
	next, _ := bw.TOTP(key, time.Now().Unix()/30+1)
	r = e.login(e.alice, "cccccccc-0000-0000-0000-000000000002", url.Values{"twoFactorProvider": {"0"}, "twoFactorToken": {next}, "twoFactorRemember": {"1"}})
	if r.status != 200 || r.body["TwoFactorToken"] == nil {
		t.Fatalf("with code: %d %v", r.status, r.body)
	}
	remember := r.body["TwoFactorToken"].(string)
	if r := e.login(e.alice, "cccccccc-0000-0000-0000-000000000002", url.Values{"twoFactorProvider": {"5"}, "twoFactorToken": {remember}}); r.status != 200 {
		t.Fatalf("remembered device: %d", r.status)
	}
	if r := e.login(e.alice, "cccccccc-0000-0000-0000-000000000003", url.Values{"twoFactorProvider": {"5"}, "twoFactorToken": {remember}}); r.status == 200 {
		t.Fatal("remember token worked on another device")
	}
	// recovery code
	_, rc := e.call("POST", "/api/two-factor/get-recover", tr.access, map[string]any{"masterPasswordHash": e.alice.hash})
	if rc["code"] == nil {
		t.Fatal("no recovery code")
	}

	// changing the master password signs every app out
	newPw := "a brand new master password"
	mk := bw.MasterKey(newPw, e.alice.email, 100000)
	newHash := bw.MasterPasswordHash(mk, newPw)
	newKey := bw.Stretch(mk).Encrypt(e.alice.key.Bytes())
	if st, _ := e.call("POST", "/api/accounts/password", tr.access, map[string]any{"masterPasswordHash": e.alice.hash, "newMasterPasswordHash": newHash, "key": newKey}); st != 200 {
		t.Fatalf("password change: %d", st)
	}
	if st, _ := e.call("GET", "/api/sync", tr.access, nil); st != 401 {
		t.Fatalf("old token still works: %d", st)
	}
	if r := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.refresh}}); r.status != 400 {
		t.Fatalf("old refresh token still works: %d", r.status)
	}
	e.alice.hash = newHash
	r = e.login(e.alice, "cccccccc-0000-0000-0000-000000000009", url.Values{"twoFactorProvider": {"8"}, "twoFactorToken": {rc["code"].(string)}})
	if r.status != 200 {
		t.Fatalf("new password + recovery code: %d %v", r.status, r.body)
	}
	if st, tf := e.call("GET", "/api/two-factor", r.access, nil); st != 200 || len(tf["data"].([]any)) != 0 {
		t.Fatalf("recovery code should turn two-step login off: %v", tf)
	}
}

func TestLiveSyncHub(t *testing.T) {
	e := newVaultEnv(t)
	ext := e.login(e.alice, "dddddddd-0000-0000-0000-000000000001", nil)
	phone := e.login(e.alice, "dddddddd-0000-0000-0000-000000000002", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, strings.Replace(e.ts.URL, "http", "ws", 1)+"/notifications/hub?access_token="+ext.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if err := ws.Write(ctx, websocket.MessageText, []byte(`{"protocol":"messagepack","version":1}`+"\x1e")); err != nil {
		t.Fatal(err)
	}
	_, hs, err := ws.Read(ctx)
	if err != nil || string(hs) != "{}\x1e" {
		t.Fatalf("handshake: %q %v", hs, err)
	}
	for e.s.bw.hub.count() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	_, c := e.call("POST", "/api/ciphers", phone.access, e.alice.login("from the phone", "a", "b"))
	_, msg, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(msg), "ReceiveMessage") || !strings.Contains(string(msg), c["id"].(string)) {
		t.Fatalf("update frame: %q", msg)
	}
	// Bob's token can't listen to Alice
	bob := e.login(e.bob, "dddddddd-0000-0000-0000-000000000003", nil)
	wb, _, err := websocket.Dial(ctx, strings.Replace(e.ts.URL, "http", "ws", 1)+"/notifications/hub?access_token="+bob.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer wb.CloseNow()
	if n := e.s.bw.hub.countFor(e.alice.userUUID(e)); n != 1 {
		t.Fatalf("Alice has %d listeners, want 1", n)
	}
	if _, _, err := websocket.Dial(ctx, strings.Replace(e.ts.URL, "http", "ws", 1)+"/notifications/hub?access_token=bad", nil); err == nil {
		t.Fatal("hub accepted a bad token")
	}
}

func (p *person) userUUID(e *vaultEnv) string {
	a, _ := e.s.store.GetVaultAccount(context.Background(), p.user.ID)
	return a.UUID
}

// Link tokens from other apps reach only the overview, never items.
func TestLinkScopes(t *testing.T) {
	req := func(method, path string) *http.Request { return httptest.NewRequest(method, path, nil) }
	if !linkAllows([]string{"vault:read"}, req("GET", "/api/v1/vault/overview")) {
		t.Fatal("vault:read should read the overview")
	}
	for _, p := range []string{"/api/v1/vault/status", "/api/v1/vault/devices", "/api/v1/vault/activity", "/api/v1/settings", "/api/sync", "/api/ciphers"} {
		if linkAllows([]string{"vault:read"}, req("GET", p)) {
			t.Errorf("vault:read reaches %s", p)
		}
	}
	if linkAllows([]string{"vault:read"}, req("PUT", "/api/v1/vault/health")) || linkAllows(nil, req("GET", "/api/v1/vault/overview")) {
		t.Fatal("scope check too loose")
	}
}

// The overview another app may read holds counts, never encrypted text.
func TestOverviewHasNoSecrets(t *testing.T) {
	e := newVaultEnv(t)
	a := e.login(e.alice, "eeeeeeee-0000-0000-0000-000000000001", nil)
	e.call("POST", "/api/ciphers", a.access, e.alice.login("Bank", "alice", "hunter2"))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/vault/overview", nil)
	r = r.WithContext(context.WithValue(r.Context(), userKey, e.alice.user))
	e.s.handleVaultOverview(rec, r)
	body := rec.Body.String()
	if strings.Contains(body, "2.") && strings.Contains(body, "|") {
		t.Fatalf("overview leaks encrypted text: %s", body)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	if m["has_vault"] != true || m["items"].(map[string]any)["logins"].(float64) != 1 {
		t.Fatalf("overview: %s", body)
	}
}

// A Vaultwarden database moves over whole: account, items, folders,
// favourites, devices (with their refresh tokens) and the authenticator.
func TestImportVaultwarden(t *testing.T) {
	e := newVaultEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "db.sqlite3")
	vw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	hash, uk, protected, pub, priv, _ := bw.NewAccountKeys("carol pw", "carol@example.com", 100000)
	salt := bw.RandomBytes(64)
	stmts := []string{
		`CREATE TABLE users (uuid TEXT, created_at TEXT, updated_at TEXT, email TEXT, name TEXT, password_hash BLOB, salt BLOB, password_iterations INT, password_hint TEXT, akey TEXT, private_key TEXT, public_key TEXT, totp_secret TEXT, totp_recover TEXT, security_stamp TEXT, equivalent_domains TEXT, excluded_globals TEXT, client_kdf_type INT, client_kdf_iter INT, verified_at TEXT, last_verifying_at TEXT, login_verify_count INT, email_new TEXT, email_new_token TEXT, enabled INT, stamp_exception TEXT, api_key TEXT, avatar_color TEXT, client_kdf_memory INT, client_kdf_parallelism INT, external_id TEXT)`,
		`CREATE TABLE folders (uuid TEXT, created_at TEXT, updated_at TEXT, user_uuid TEXT, name TEXT)`,
		`CREATE TABLE folders_ciphers (cipher_uuid TEXT, folder_uuid TEXT)`,
		`CREATE TABLE favorites (user_uuid TEXT, cipher_uuid TEXT)`,
		`CREATE TABLE archives (user_uuid TEXT, cipher_uuid TEXT, archived_at TEXT)`,
		`CREATE TABLE ciphers (uuid TEXT, created_at TEXT, updated_at TEXT, user_uuid TEXT, organization_uuid TEXT, atype INT, name TEXT, notes TEXT, fields TEXT, data TEXT, password_history TEXT, deleted_at TEXT, reprompt INT, key TEXT)`,
		`CREATE TABLE devices (uuid TEXT, created_at TEXT, updated_at TEXT, user_uuid TEXT, name TEXT, atype INT, push_token TEXT, refresh_token TEXT, twofactor_remember TEXT, push_uuid TEXT)`,
		`CREATE TABLE twofactor (uuid TEXT, user_uuid TEXT, atype INT, enabled INT, data TEXT, last_used INT)`,
		`CREATE TABLE attachments (id TEXT, cipher_uuid TEXT, file_name TEXT, file_size INT, akey TEXT)`,
		`CREATE TABLE sends (uuid TEXT, user_uuid TEXT)`,
		`CREATE TABLE users_organizations (uuid TEXT, user_uuid TEXT)`,
	}
	for _, q := range stmts {
		if _, err := vw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	const cu = "c0c0c0c0-0000-0000-0000-000000000001"
	mustExec := func(q string, args ...any) {
		if _, err := vw.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`INSERT INTO users VALUES (?, '2026-01-02 03:04:05.123456', '2026-02-02 03:04:05', 'carol@example.com', 'Carol', ?, ?, 1000, 'hint', ?, ?, ?, NULL, 'RECOVER', 'stamp-1', '[]', '[]', 0, 100000, NULL, NULL, 0, NULL, NULL, 1, NULL, NULL, NULL, NULL, NULL, NULL)`,
		cu, bw.HashMaster(hash, salt, 1000), salt, protected, priv, pub)
	mustExec(`INSERT INTO folders VALUES ('f0000000-0000-0000-0000-000000000001', '2026-01-03 00:00:00', '2026-01-03 00:00:00', ?, ?)`, cu, uk.EncryptString("Bills"))
	mustExec(`INSERT INTO ciphers VALUES ('ab000000-0000-0000-0000-000000000001', '2026-01-04 00:00:00', '2026-01-05 00:00:00', ?, NULL, 1, ?, NULL, NULL, ?, NULL, NULL, 0, NULL)`,
		cu, uk.EncryptString("Power company"), `{"username":"`+uk.EncryptString("carol")+`","password":"`+uk.EncryptString("pw")+`","uris":[]}`)
	mustExec(`INSERT INTO ciphers VALUES ('ab000000-0000-0000-0000-000000000002', '2026-01-04 00:00:00', '2026-01-05 00:00:00', ?, NULL, 2, ?, ?, NULL, '{"type":0}', NULL, '2026-03-01 00:00:00', 0, NULL)`,
		cu, uk.EncryptString("Old note"), uk.EncryptString("body"))
	mustExec(`INSERT INTO folders_ciphers VALUES ('ab000000-0000-0000-0000-000000000001', 'f0000000-0000-0000-0000-000000000001')`)
	mustExec(`INSERT INTO favorites VALUES (?, 'ab000000-0000-0000-0000-000000000001')`, cu)
	mustExec(`INSERT INTO devices VALUES ('d0000000-0000-0000-0000-000000000001', '2026-01-02 00:00:00', '2026-11-01 00:00:00', ?, 'iPhone', 1, 'push', 'REFRESH-SECRET', NULL, NULL)`, cu)
	mustExec(`INSERT INTO twofactor VALUES ('t1', ?, 0, 1, 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', 5)`, cu)
	mustExec(`INSERT INTO attachments VALUES ('a1', 'ab000000-0000-0000-0000-000000000001', 'x', 1, 'k')`)
	vw.Close()

	rep, err := e.s.ImportVaultwarden(context.Background(), path, VWOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Accounts) != 1 || rep.Accounts[0].Status != "imported" || rep.Accounts[0].Items != 2 || rep.Accounts[0].Devices != 1 || !rep.Accounts[0].TwoFactor {
		t.Fatalf("report: %+v", rep)
	}
	if len(rep.Notes) == 0 {
		t.Fatal("attachments not mentioned")
	}
	// the imported person signs in with the same master password (and code)
	carol := &person{email: "carol@example.com", hash: hash, key: uk}
	code, _ := bw.TOTP("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", time.Now().Unix()/30)
	r := e.login(carol, "d0000000-0000-0000-0000-000000000001", url.Values{"twoFactorProvider": {"0"}, "twoFactorToken": {code}})
	if r.status != 200 {
		t.Fatalf("imported sign-in: %d %v", r.status, r.body)
	}
	_, sync := e.call("GET", "/api/sync", r.access, nil)
	cs := sync["ciphers"].([]any)
	if len(cs) != 2 {
		t.Fatalf("items: %d", len(cs))
	}
	for _, c := range cs {
		cm := c.(map[string]any)
		if cm["id"] == "ab000000-0000-0000-0000-000000000001" && (cm["folderId"] != "f0000000-0000-0000-0000-000000000001" || cm["favorite"] != true) {
			t.Fatalf("folder/favourite lost: %v", cm)
		}
		if cm["id"] == "ab000000-0000-0000-0000-000000000002" && cm["deletedDate"] == nil {
			t.Fatal("bin lost")
		}
	}
	// the device's refresh secret came along: an app signed in to Vaultwarden keeps going
	now := time.Now().Unix()
	refresh, _ := bw.Sign(e.s.bwKey(), bw.RefreshClaims{Nbf: now, Exp: now + 60, Iss: e.s.bw.issuer, Sub: "password", DeviceToken: "REFRESH-SECRET", Token: json.RawMessage("null")})
	if r := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}); r.status != 200 {
		t.Fatalf("Vaultwarden refresh token: %d", r.status)
	}
	// a second import skips; with replace it replaces
	rep, _ = e.s.ImportVaultwarden(context.Background(), path, VWOptions{})
	if rep.Accounts[0].Status != "skipped" {
		t.Fatalf("second import: %+v", rep.Accounts[0])
	}
	rep, _ = e.s.ImportVaultwarden(context.Background(), path, VWOptions{Replace: true})
	if rep.Accounts[0].Status != "replaced" || rep.Accounts[0].Items != 2 {
		t.Fatalf("replace: %+v", rep.Accounts[0])
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the Vaultwarden file must be left alone")
	}
}

func TestTOTPAndEncString(t *testing.T) {
	// RFC 6238 test vector (SHA-1, 30 s): 59 s → 94287082, last 6 digits
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	if c, _ := bw.TOTP(secret, 59/30); c != "287082" {
		t.Fatalf("TOTP = %s", c)
	}
	k := bw.NewSymKey()
	enc := k.EncryptString("hello")
	if out, err := k.Decrypt(enc); err != nil || string(out) != "hello" {
		t.Fatalf("round trip: %q %v", out, err)
	}
	if _, err := bw.NewSymKey().Decrypt(enc); err == nil {
		t.Fatal("another key decrypted it")
	}
}
