package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// fakeAuthenticator is a passkey in software: one ES256 key, discoverable.
type fakeAuthenticator struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	credID []byte
	user   []byte
	count  uint32
	origin string
	rpID   string
}

var b64u = base64.RawURLEncoding

func newFakeAuthenticator(t *testing.T, origin string) *fakeAuthenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	u, _ := url.Parse(origin)
	return &fakeAuthenticator{t: t, key: k, credID: id, origin: origin, rpID: u.Hostname()}
}

func (a *fakeAuthenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *fakeAuthenticator) authData(flags byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, a.count)
	out = append(out, c...)
	return append(out, attested...)
}

// create answers navigator.credentials.create with the server's options.
func (a *fakeAuthenticator) create(opts map[string]any) map[string]any {
	pk, _ := opts["publicKey"].(map[string]any)
	if pk == nil {
		pk = opts
	}
	user := pk["user"].(map[string]any)
	uid, err := b64u.DecodeString(strings.TrimRight(user["id"].(string), "="))
	if err != nil {
		a.t.Fatalf("user id: %v", err)
	}
	a.user = uid
	x, y := a.key.X.FillBytes(make([]byte, 32)), a.key.Y.FillBytes(make([]byte, 32))
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	att := make([]byte, 16) // aaguid
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(a.credID)))
	att = append(append(append(att, l...), a.credID...), cose...)
	ad := a.authData(0x01|0x04|0x40, att) // UP, UV, AT
	obj, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	cd := a.clientData("webauthn.create", pk["challenge"].(string))
	return map[string]any{"id": b64u.EncodeToString(a.credID), "rawId": b64u.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u.EncodeToString(cd), "attestationObject": b64u.EncodeToString(obj)}, "extensions": map[string]any{}}
}

// get answers navigator.credentials.get.
func (a *fakeAuthenticator) get(opts map[string]any) map[string]any {
	pk, _ := opts["publicKey"].(map[string]any)
	if pk == nil {
		pk = opts
	}
	a.count++
	ad := a.authData(0x01|0x04, nil)
	cd := a.clientData("webauthn.get", pk["challenge"].(string))
	h := sha256.Sum256(cd)
	sum := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, sum[:])
	return map[string]any{"id": b64u.EncodeToString(a.credID), "rawId": b64u.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u.EncodeToString(cd), "authenticatorData": b64u.EncodeToString(ad),
			"signature": b64u.EncodeToString(sig), "userHandle": b64u.EncodeToString(a.user)}}
}

func (e *vaultEnv) passkeyLogin(a *fakeAuthenticator, extra url.Values, mutate func(map[string]any)) tokenRes {
	res, err := http.Get(e.ts.URL + "/identity/accounts/webauthn/assertion-options")
	if err != nil {
		e.t.Fatal(err)
	}
	var o map[string]any
	_ = json.NewDecoder(res.Body).Decode(&o)
	res.Body.Close()
	resp := a.get(o["options"].(map[string]any))
	if mutate != nil {
		mutate(resp)
	}
	dr, _ := json.Marshal(resp)
	f := url.Values{"grant_type": {"webauthn"}, "token": {o["token"].(string)}, "deviceResponse": {string(dr)}, "scope": {"api offline_access"},
		"client_id": {"web"}, "deviceType": {"9"}, "deviceIdentifier": {"22222222-2222-2222-2222-222222222222"}, "deviceName": {"chrome"}}
	for k, v := range extra {
		f[k] = v
	}
	return e.token(f)
}

func TestPasskeySignInAndUnlock(t *testing.T) {
	e := newVaultEnv(t)
	// WebAuthn needs a domain, not an IP address
	e.s.cfg.BaseURL = strings.Replace(e.s.cfg.BaseURL, "127.0.0.1", "localhost", 1)
	origin := e.s.cfg.BaseURL
	tr := e.login(e.alice, "11111111-1111-1111-1111-111111111111", nil)
	if tr.status != 200 {
		t.Fatalf("login: %d %v", tr.status, tr.body)
	}
	tok := tr.access

	// adding one needs the master password
	if st, _ := e.call("POST", "/api/webauthn/attestation-options", tok, map[string]any{"masterPasswordHash": "nope"}); st != 400 {
		t.Fatalf("wrong password allowed: %d", st)
	}
	st, opts := e.call("POST", "/api/webauthn/attestation-options", tok, map[string]any{"masterPasswordHash": e.alice.hash})
	if st != 200 || opts["token"] == nil {
		t.Fatalf("attestation options: %d %v", st, opts)
	}
	o := opts["options"].(map[string]any)
	if sel := o["authenticatorSelection"].(map[string]any); sel["residentKey"] != "required" || sel["userVerification"] != "required" {
		t.Fatalf("selection: %v", sel)
	}
	a := newFakeAuthenticator(t, origin)
	created := a.create(o)
	ukey, pub, priv := "4.QUJD", e.alice.key.EncryptString("pub"), e.alice.key.EncryptString("priv")
	// half the keys: refused
	if st, _ := e.call("POST", "/api/webauthn", tok, map[string]any{"deviceResponse": created, "name": "x", "token": opts["token"], "encryptedUserKey": ukey}); st != 400 {
		t.Fatalf("half keys: %d", st)
	}
	// that spent the challenge? No: the token is checked first, so start again
	_, opts = e.call("POST", "/api/webauthn/attestation-options", tok, map[string]any{"masterPasswordHash": e.alice.hash})
	created = a.create(opts["options"].(map[string]any))
	st, saved := e.call("POST", "/api/webauthn", tok, map[string]any{"deviceResponse": created, "name": "MacBook Touch ID", "token": opts["token"], "supportsPrf": true,
		"encryptedUserKey": ukey, "encryptedPublicKey": pub, "encryptedPrivateKey": priv})
	if st != 200 || saved["prfStatus"] != float64(0) || saved["name"] != "MacBook Touch ID" {
		t.Fatalf("save: %d %v", st, saved)
	}
	// the same token twice: refused
	if st, _ := e.call("POST", "/api/webauthn", tok, map[string]any{"deviceResponse": created, "name": "again", "token": opts["token"]}); st != 400 {
		t.Fatalf("token reused: %d", st)
	}
	st, list := e.call("GET", "/api/webauthn", tok, nil)
	if st != 200 || len(list["data"].([]any)) != 1 {
		t.Fatalf("list: %d %v", st, list)
	}

	// sign in with it: no email, no password, keys to unlock come back
	r := e.passkeyLogin(a, nil, nil)
	if r.status != 200 || r.access == "" {
		t.Fatalf("passkey login: %d %v", r.status, r.body)
	}
	prf, _ := r.body["UserDecryptionOptions"].(map[string]any)["WebAuthnPrfOption"].(map[string]any)
	if prf["EncryptedUserKey"] != ukey || prf["EncryptedPrivateKey"] != priv {
		t.Fatalf("prf option: %v", r.body["UserDecryptionOptions"])
	}
	if r.body["Key"] != tr.body["Key"] {
		t.Fatal("master-password key missing")
	}
	if st, _ := e.call("GET", "/api/sync", r.access, nil); st != 200 {
		t.Fatalf("sync with passkey token: %d", st)
	}
	// the refresh token works like a password sign-in's
	if rr := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.refresh}, "client_id": {"web"}}); rr.status != 200 {
		t.Fatalf("refresh: %d", rr.status)
	}

	// a forged signature, a passkey nobody added, an old counter: refused
	if r := e.passkeyLogin(a, nil, func(m map[string]any) {
		m["response"].(map[string]any)["signature"] = b64u.EncodeToString([]byte("forged"))
	}); r.status != 400 {
		t.Fatalf("forged: %d", r.status)
	}
	stranger := newFakeAuthenticator(t, origin)
	stranger.user = []byte("nobody")
	if r := e.passkeyLogin(stranger, nil, nil); r.status != 400 || !strings.Contains(r.body["message"].(string), "isn't on any vault") {
		t.Fatalf("stranger: %d %v", r.status, r.body)
	}
	a.count = 0
	if r := e.passkeyLogin(a, nil, nil); r.status != 400 {
		t.Fatalf("counter went back: %d", r.status)
	}
	a.count = 100

	// two-step login doesn't stop a passkey (it already is two factors)
	if err := e.s.store.SaveTwoFactor(t.Context(), &store.TwoFactor{UserID: e.alice.user.ID, Type: tfAuthenticator, Enabled: true, Data: "JBSWY3DPEHPK3PXP"}); err != nil {
		t.Fatal(err)
	}
	if r := e.passkeyLogin(a, nil, nil); r.status != 200 {
		t.Fatalf("passkey with two-step on: %d %v", r.status, r.body)
	}

	// our web vault's sign-in: also a Pocket Vault session, only from its own page
	if r := e.passkeyLogin(a, url.Values{"pocket_session": {"1"}}, nil); r.status != 403 {
		t.Fatalf("pocket session without origin: %d", r.status)
	}
	res, err := http.Get(e.ts.URL + "/identity/accounts/webauthn/assertion-options")
	if err != nil {
		t.Fatal(err)
	}
	var lo map[string]any
	_ = json.NewDecoder(res.Body).Decode(&lo)
	res.Body.Close()
	dr, _ := json.Marshal(a.get(lo["options"].(map[string]any)))
	f := url.Values{"grant_type": {"webauthn"}, "token": {lo["token"].(string)}, "deviceResponse": {string(dr)}, "scope": {"api offline_access"}, "pocket_session": {"1"},
		"client_id": {"web"}, "deviceType": {"9"}, "deviceIdentifier": {"22222222-2222-2222-2222-222222222222"}, "deviceName": {"chrome"}}
	req, _ := http.NewRequest("POST", e.ts.URL+"/identity/connect/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || len(res.Cookies()) == 0 {
		t.Fatalf("pocket session: %d %v", res.StatusCode, res.Cookies())
	}

	// the vault status counts them
	pks, _ := e.s.store.ListPasskeys(t.Context(), e.alice.user.ID)
	if len(pks) != 1 || !pks[0].Unlocks() || pks[0].LastUsedAt == nil {
		t.Fatalf("stored: %+v", pks)
	}

	// removing needs the master password
	id := saved["id"].(string)
	if st, _ := e.call("POST", "/api/webauthn/"+id+"/delete", tok, map[string]any{"masterPasswordHash": "nope"}); st != 400 {
		t.Fatalf("delete without password: %d", st)
	}
	if st, _ := e.call("POST", "/api/webauthn/"+id+"/delete", tok, map[string]any{"masterPasswordHash": e.alice.hash}); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if r := e.passkeyLogin(a, nil, nil); r.status != 400 {
		t.Fatalf("removed passkey still signs in: %d", r.status)
	}
	// Bob can't see or remove Alice's
	if st, l := e.call("GET", "/api/webauthn", e.login(e.bob, "33333333-3333-3333-3333-333333333333", nil).access, nil); st != 200 || len(l["data"].([]any)) != 0 {
		t.Fatalf("bob list: %d %v", st, l)
	}
}
