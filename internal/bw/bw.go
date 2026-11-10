// Package bw holds the pieces of the Bitwarden protocol the server needs:
// RS256 tokens, the server-side master password hash, authenticator codes
// and the MessagePack frames of the live-sync hub.
//
// The apps do every bit of vault encryption themselves; nothing here can
// decrypt an item.
package bw

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// ---- signing key ----

// LoadOrCreateKey reads an RSA key in PEM (PKCS#1 or PKCS#8, the form
// Vaultwarden's rsa_key.pem uses), or makes a new 2048-bit one there.
func LoadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		return ParseKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// ParseKey parses an RSA private key in PEM.
func ParseKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not a PEM key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rk, nil
}

// ---- RS256 JWT ----

var b64 = base64.RawURLEncoding

// Sign makes an RS256 JWT of claims.
func Sign(key *rsa.PrivateKey, claims any) (string, error) {
	head := b64.EncodeToString([]byte(`{"typ":"JWT","alg":"RS256"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	msg := head + "." + b64.EncodeToString(body)
	sum := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return msg + "." + b64.EncodeToString(sig), nil
}

// ErrToken is any reason a token is not accepted.
var ErrToken = errors.New("invalid token")

// Verify checks an RS256 JWT's signature, issuer and dates and decodes
// its claims into out.
func Verify(key *rsa.PublicKey, tok, issuer string, out any) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ErrToken
	}
	head, err := b64.DecodeString(parts[0])
	if err != nil {
		return ErrToken
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(head, &h) != nil || h.Alg != "RS256" {
		return ErrToken
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return ErrToken
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return ErrToken
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return ErrToken
	}
	var std struct {
		Nbf int64  `json:"nbf"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if json.Unmarshal(body, &std) != nil {
		return ErrToken
	}
	now := time.Now().Unix()
	if std.Iss != issuer || std.Exp < now || std.Nbf > now+60 {
		return ErrToken
	}
	if err := json.Unmarshal(body, out); err != nil {
		return ErrToken
	}
	return nil
}

// LoginClaims are an access token's claims, as the apps read them.
type LoginClaims struct {
	Nbf           int64    `json:"nbf"`
	Exp           int64    `json:"exp"`
	Iss           string   `json:"iss"`
	Sub           string   `json:"sub"` // the account uuid
	Premium       bool     `json:"premium"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	SStamp        string   `json:"sstamp"`
	Device        string   `json:"device"`
	DeviceType    string   `json:"devicetype"`
	ClientID      string   `json:"client_id"`
	Scope         []string `json:"scope"`
	Amr           []string `json:"amr"`
}

// RefreshClaims wrap a device's refresh secret (the same shape Vaultwarden
// uses, so apps signed in there stay signed in).
type RefreshClaims struct {
	Nbf         int64           `json:"nbf"`
	Exp         int64           `json:"exp"`
	Iss         string          `json:"iss"`
	Sub         string          `json:"sub"` // the login method: "password"
	DeviceToken string          `json:"device_token"`
	Token       json.RawMessage `json:"token"`
}

// RememberClaims are a "remember this device" token for two-step login.
type RememberClaims struct {
	Nbf      int64  `json:"nbf"`
	Exp      int64  `json:"exp"`
	Iss      string `json:"iss"`
	Sub      string `json:"sub"` // device uuid
	UserUUID string `json:"user_uuid"`
}

// ---- master password ----

// HashMaster is the server-side hash of the hash an app sends: PBKDF2-SHA256.
func HashMaster(clientHash string, salt []byte, iterations int) []byte {
	return pbkdf2.Key([]byte(clientHash), salt, iterations, 32, sha256.New)
}

// CheckMaster compares an app's hash with the stored one in constant time.
func CheckMaster(clientHash string, salt, stored []byte, iterations int) bool {
	if clientHash == "" || len(stored) == 0 || iterations <= 0 {
		return false
	}
	return subtle.ConstantTimeCompare(HashMaster(clientHash, salt, iterations), stored) == 1
}

// RandomBytes returns n random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// RandomBase32 is n random bytes in base32 without padding (TOTP secrets,
// recovery codes).
func RandomBase32(n int) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(RandomBytes(n))
}

// ---- authenticator codes (RFC 6238, SHA-1, 30 s, 6 digits) ----

// TOTP returns the code for a base32 secret at a time step.
func TOTP(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(strings.ReplaceAll(secret, " ", ""), "=")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// CheckTOTP looks for code at the current step ±1 and returns the matching
// step, which must be newer than lastUsed (no code works twice).
func CheckTOTP(secret, code string, lastUsed int64, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	cur := now.Unix() / 30
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		want, err := TOTP(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			if step <= lastUsed {
				return 0, false
			}
			return step, true
		}
	}
	return 0, false
}
