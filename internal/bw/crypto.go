package bw

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// The client side of Bitwarden's encryption, for the demo vault and the
// tests only: the server never sees a master password in real use.

// MasterKey derives the master key from a password (PBKDF2-SHA256, the
// lowercased email as salt).
func MasterKey(password, email string, iterations int) []byte {
	return pbkdf2.Key([]byte(password), []byte(strings.ToLower(strings.TrimSpace(email))), iterations, 32, sha256.New)
}

// MasterPasswordHash is what an app sends to sign in.
func MasterPasswordHash(masterKey []byte, password string) string {
	return base64.StdEncoding.EncodeToString(pbkdf2.Key(masterKey, []byte(password), 1, 32, sha256.New))
}

// SymKey is a 64-byte key: 32 for AES-256, 32 for HMAC-SHA256.
type SymKey struct{ Enc, Mac []byte }

// Stretch turns a master key into an encryption + MAC key (HKDF-Expand).
func Stretch(masterKey []byte) SymKey {
	expand := func(info string) []byte {
		out := make([]byte, 32)
		r := hkdf.Expand(sha256.New, masterKey, []byte(info))
		_, _ = r.Read(out)
		return out
	}
	return SymKey{Enc: expand("enc"), Mac: expand("mac")}
}

// KeyFrom splits 64 bytes into a SymKey.
func KeyFrom(b []byte) (SymKey, error) {
	if len(b) != 64 {
		return SymKey{}, errors.New("a key is 64 bytes")
	}
	return SymKey{Enc: b[:32], Mac: b[32:]}, nil
}

// Bytes is the 64-byte form.
func (k SymKey) Bytes() []byte { return append(append([]byte{}, k.Enc...), k.Mac...) }

// NewSymKey makes a random key.
func NewSymKey() SymKey { k, _ := KeyFrom(RandomBytes(64)); return k }

// Encrypt makes an EncString of type 2 (AES-256-CBC, HMAC-SHA256).
func (k SymKey) Encrypt(plain []byte) string {
	iv := RandomBytes(16)
	pad := 16 - len(plain)%16
	data := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	blk, _ := aes.NewCipher(k.Enc)
	ct := make([]byte, len(data))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, data)
	m := hmac.New(sha256.New, k.Mac)
	m.Write(iv)
	m.Write(ct)
	e := base64.StdEncoding.EncodeToString
	return "2." + e(iv) + "|" + e(ct) + "|" + e(m.Sum(nil))
}

// EncryptString is Encrypt for text.
func (k SymKey) EncryptString(s string) string { return k.Encrypt([]byte(s)) }

// Decrypt opens an EncString of type 2.
func (k SymKey) Decrypt(enc string) ([]byte, error) {
	if !strings.HasPrefix(enc, "2.") {
		return nil, errors.New("only type 2 is supported")
	}
	parts := strings.Split(enc[2:], "|")
	if len(parts) != 3 {
		return nil, errors.New("bad EncString")
	}
	d := base64.StdEncoding.DecodeString
	iv, err1 := d(parts[0])
	ct, err2 := d(parts[1])
	mac, err3 := d(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != 16 || len(ct)%16 != 0 || len(ct) == 0 {
		return nil, errors.New("bad EncString")
	}
	m := hmac.New(sha256.New, k.Mac)
	m.Write(iv)
	m.Write(ct)
	if !hmac.Equal(m.Sum(nil), mac) {
		return nil, errors.New("wrong key")
	}
	blk, _ := aes.NewCipher(k.Enc)
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > 16 || pad > len(out) {
		return nil, errors.New("bad padding")
	}
	return out[:len(out)-pad], nil
}

// NewAccountKeys makes what a new vault needs from a master password: the
// sign-in hash, the user key (returned) wrapped with the master key, and an
// RSA key pair (private half wrapped with the user key).
func NewAccountKeys(password, email string, iterations int) (hash string, user SymKey, protected, pub, priv string, err error) {
	mk := MasterKey(password, email, iterations)
	hash = MasterPasswordHash(mk, password)
	user = NewSymKey()
	protected = Stretch(mk).Encrypt(user.Bytes())
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	der, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		return
	}
	spki, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if err != nil {
		return
	}
	pub = base64.StdEncoding.EncodeToString(spki)
	priv = user.Encrypt(der)
	return
}
