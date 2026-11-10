package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// DemoMasterPassword unlocks the demo vault (DEMO_DATA=true).
const DemoMasterPassword = "correct horse battery staple"

// seedDemo gives the owner a vault full of plausible items, encrypted the
// way the apps do it (DEMO_DATA=true, for screenshots and trying the app).
// Some passwords are weak or used twice on purpose, so Health has something
// to show. Runs once.
func (s *Server) seedDemo(ctx context.Context, owner int64) error {
	ctx = context.WithoutCancel(ctx)
	key := fmt.Sprintf("seeded:%d:demo", owner)
	if _, _, done := s.store.CacheGet(ctx, key); done {
		return nil
	}
	if _, err := s.store.GetVaultAccount(ctx, owner); err == nil {
		return s.store.CachePut(ctx, key, "1")
	}
	u, err := s.store.GetUser(ctx, owner)
	if err != nil {
		return err
	}
	rng := rand.New(rand.NewSource(42))
	const iter = 600000
	hash, uk, protected, pub, priv, err := bw.NewAccountKeys(DemoMasterPassword, u.Email, iter)
	if err != nil {
		return err
	}
	salt := bw.RandomBytes(64)
	now := time.Now().UTC()
	created := now.AddDate(0, -14, 0).Format(store.BWTime)
	a := &store.VaultAccount{UserID: owner, UUID: uuid.NewString(), Email: u.Email, Name: firstNonEmpty(u.Name, "Demo"), MasterSalt: salt,
		MasterHash: bw.HashMaster(hash, salt, 600000), MasterIterations: 600000, PasswordHint: "the classic four words", AKey: protected,
		PrivateKey: priv, PublicKey: pub, SecurityStamp: uuid.NewString(), KdfType: 0, KdfIterations: iter, Enabled: true, CreatedAt: created}
	if err := s.store.CreateVaultAccount(ctx, a); err != nil {
		return err
	}
	enc := uk.EncryptString
	folders := map[string]string{}
	for i, name := range []string{"Work", "Personal", "Money", "Home"} {
		f := &store.Folder{UserID: owner, UUID: uuid.NewString(), Name: enc(name), CreatedAt: now.AddDate(0, -13, i).Format(store.BWTime)}
		if err := s.store.SaveFolder(ctx, f); err != nil {
			return err
		}
		folders[name] = f.UUID
	}
	when := func(daysAgo int) string {
		return now.AddDate(0, 0, -daysAgo).Add(-time.Duration(rng.Intn(36000)) * time.Second).Format(store.BWTime)
	}
	strong := func() string {
		const set = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*-_"
		b := make([]byte, 18+rng.Intn(6))
		for i := range b {
			b[i] = set[rng.Intn(len(set))]
		}
		return string(b)
	}
	save := func(c *store.Cipher) error { return s.store.SaveCipher(ctx, c, true) }
	type login struct {
		name, uri, user, pass, folder, totp string
		fav                                 bool
		age                                 int
	}
	logins := []login{
		{"GitHub", "https://github.com", "alex.dev", "", "Work", "JBSWY3DPEHPK3PXP", true, 400},
		{"Google", "https://accounts.google.com", "alex.morgan@gmail.com", "", "Personal", "KRSXG5CTMVRXEZLU", true, 380},
		{"Microsoft 365", "https://login.microsoftonline.com", "alex@northwind.example", "", "Work", "", false, 300},
		{"Slack", "https://northwind.slack.com", "alex@northwind.example", "", "Work", "", false, 280},
		{"Jira", "https://northwind.atlassian.net", "alex@northwind.example", "Summer2024!", "Work", "", false, 520},
		{"AWS console", "https://console.aws.amazon.com", "alex-admin", "", "Work", "GEZDGNBVGY3TQOJQ", false, 200},
		{"Amazon", "https://www.amazon.com", "alex.morgan@gmail.com", "Summer2024!", "Personal", "", false, 610},
		{"Netflix", "https://www.netflix.com", "alex.morgan@gmail.com", "netflix123", "Personal", "", false, 700},
		{"Spotify", "https://open.spotify.com", "alexmorgan", "", "Personal", "", false, 150},
		{"Instagram", "https://www.instagram.com", "alex.morgan", "", "Personal", "", false, 90},
		{"Reddit", "https://www.reddit.com", "quiet_alex", "password1", "Personal", "", false, 820},
		{"Dropbox", "https://www.dropbox.com", "alex.morgan@gmail.com", "", "Personal", "", false, 60},
		{"Duolingo", "https://www.duolingo.com", "alexlearns", "", "Personal", "", false, 30},
		{"Northwind Bank", "https://online.northwindbank.example", "alexm1985", "", "Money", "", true, 120},
		{"PayPal", "https://www.paypal.com", "alex.morgan@gmail.com", "", "Money", "MFRGGZDFMZTWQ2LK", false, 250},
		{"Revolut", "https://app.revolut.com", "+44 7700 900123", "", "Money", "", false, 80},
		{"Tax office", "https://www.tax.service.example", "AB123456C", "Summer2024!", "Money", "", false, 400},
		{"Electricity", "https://my.brightpower.example", "alex.morgan@gmail.com", "", "Home", "", false, 330},
		{"Wi-Fi router", "http://192.168.1.1", "admin", "admin", "Home", "", false, 900},
		{"Home Assistant", "https://ha.home.example", "alex", "", "Home", "", false, 45},
		{"Water company", "https://account.clearwater.example", "alex.morgan@gmail.com", "", "Home", "", false, 210},
		{"Booking.com", "https://www.booking.com", "alex.morgan@gmail.com", "", "", "", false, 175},
		{"Airbnb", "https://www.airbnb.com", "alex.morgan@gmail.com", "", "", "", false, 160},
		{"Uber", "https://auth.uber.com", "+44 7700 900123", "", "", "", false, 140},
		{"Steam", "https://store.steampowered.com", "quietalex", "", "Personal", "", false, 450},
		{"LinkedIn", "https://www.linkedin.com", "alex.morgan@gmail.com", "", "Work", "", false, 365},
		{"Figma", "https://www.figma.com", "alex@northwind.example", "", "Work", "", false, 95},
		{"Zoom", "https://zoom.us", "alex@northwind.example", "zoom2023", "Work", "", false, 640},
	}
	for i, l := range logins {
		pass := l.pass
		if pass == "" {
			pass = strong()
		}
		uris := []any{map[string]any{"uri": enc(l.uri), "match": nil}}
		data := map[string]any{"username": enc(l.user), "password": enc(pass), "uris": uris, "passwordRevisionDate": nil, "fido2Credentials": []any{}, "autofillOnPageLoad": nil}
		if l.totp != "" {
			data["totp"] = enc(l.totp)
		}
		var hist *string
		if i%5 == 0 {
			hist = jsonText([]any{map[string]any{"password": enc(strong()), "lastUsedDate": when(l.age + 30)}})
			data["passwordRevisionDate"] = when(l.age / 2)
		}
		c := &store.Cipher{UserID: owner, UUID: uuid.NewString(), Type: 1, Name: enc(l.name), Data: mustJSON(data), Favorite: l.fav,
			CreatedAt: when(l.age), UpdatedAt: when(l.age / 3), PasswordHistory: hist}
		if f, ok := folders[l.folder]; ok {
			c.FolderUUID = &f
		}
		if l.name == "AWS console" {
			c.Fields = jsonText([]any{map[string]any{"name": enc("Account ID"), "value": enc("4821-9930-1174"), "type": 0, "linkedId": nil},
				map[string]any{"name": enc("Recovery email"), "value": enc("alex.backup@proton.example"), "type": 1, "linkedId": nil}})
		}
		if err := save(c); err != nil {
			return err
		}
	}
	money := folders["Money"]
	cards := []map[string]string{
		{"name": "Northwind Visa", "cardholderName": "Alex Morgan", "brand": "Visa", "number": "4111111111111111", "expMonth": "8", "expYear": fmt.Sprint(now.Year() + 2), "code": "123"},
		{"name": "Travel Mastercard", "cardholderName": "Alex Morgan", "brand": "Mastercard", "number": "5555555555554444", "expMonth": fmt.Sprint(int(now.Month())%12 + 1), "expYear": fmt.Sprint(now.Year()), "code": "456"},
	}
	for i, cd := range cards {
		data := map[string]any{}
		for k, v := range cd {
			if k != "name" {
				data[k] = enc(v)
			}
		}
		c := &store.Cipher{UserID: owner, UUID: uuid.NewString(), Type: 3, Name: enc(cd["name"]), Data: mustJSON(data), FolderUUID: &money,
			CreatedAt: when(300 - i*100), UpdatedAt: when(200 - i*100), Notes: ptr(enc("Call +44 20 7946 0000 if lost."))}
		if err := save(c); err != nil {
			return err
		}
	}
	idData := map[string]any{"title": enc("Mr"), "firstName": enc("Alex"), "lastName": enc("Morgan"), "email": enc("alex.morgan@gmail.com"),
		"phone": enc("+44 7700 900123"), "address1": enc("12 Willow Lane"), "city": enc("Bristol"), "postalCode": enc("BS1 4ST"), "country": enc("United Kingdom"),
		"passportNumber": enc("533401927"), "licenseNumber": enc("MORGA853214AM9IJ")}
	pers := folders["Personal"]
	if err := save(&store.Cipher{UserID: owner, UUID: uuid.NewString(), Type: 4, Name: enc("Alex Morgan"), Data: mustJSON(idData), FolderUUID: &pers, Favorite: true, CreatedAt: when(390), UpdatedAt: when(40)}); err != nil {
		return err
	}
	notes := []struct{ name, body, folder string }{
		{"Wi-Fi at home", "Network: Willow-5G\nPassword: maple-otter-seventeen-cloud", "Home"},
		{"Passport", "Number 533401927\nIssued 14 March 2019, expires 14 March 2029\nKept in the blue folder, top drawer.", "Personal"},
		{"Bike lock", "Code 4-1-8-2", "Home"},
		{"Recovery codes — GitHub", strings.Join([]string{"a1b2c-3d4e5", "f6g7h-8i9j0", "k1l2m-3n4o5", "p6q7r-8s9t0"}, "\n"), "Work"},
	}
	for i, n := range notes {
		f := folders[n.folder]
		if err := save(&store.Cipher{UserID: owner, UUID: uuid.NewString(), Type: 2, Name: enc(n.name), Notes: ptr(enc(n.body)), Data: `{"type":0}`, FolderUUID: &f, CreatedAt: when(250 - i*40), UpdatedAt: when(100 - i*20)}); err != nil {
			return err
		}
	}
	gone := when(6)
	if err := save(&store.Cipher{UserID: owner, UUID: uuid.NewString(), Type: 1, Name: enc("Old forum"),
		Data:      mustJSON(map[string]any{"username": enc("alex85"), "password": enc("letmein"), "uris": []any{map[string]any{"uri": enc("https://forum.example"), "match": nil}}}),
		CreatedAt: when(1500), UpdatedAt: gone, DeletedAt: &gone}); err != nil {
		return err
	}
	devices := []struct {
		name string
		typ  int
		age  int
	}{{"iPhone16,2", 1, 0}, {"chrome", 2, 0}, {"macos", 7, 2}, {"firefox", 3, 40}}
	for _, d := range devices {
		dev := &store.Device{UserID: owner, UUID: uuid.NewString(), Name: d.name, Type: d.typ, RefreshToken: store.RandomToken(48), CreatedAt: when(300), UpdatedAt: when(d.age), LastIP: "192.168.1." + fmt.Sprint(20+rng.Intn(60))}
		if err := s.store.SaveDevice(ctx, dev, false); err != nil {
			return err
		}
	}
	for _, e := range []store.VaultEvent{{Kind: "imported", Detail: "from Vaultwarden: 36 items, 4 folders, 4 apps"}, {Kind: "new_device", DeviceName: "iPhone16,2", IP: "192.168.1.31"},
		{Kind: "signed_in", DeviceName: "chrome", IP: "192.168.1.44"}, {Kind: "signin_failed", DeviceName: "chrome", IP: "203.0.113.9"}, {Kind: "signed_in", DeviceName: "macos", IP: "192.168.1.52"}} {
		s.store.AddVaultEvent(ctx, owner, e)
	}
	s.log.Info("demo vault created", "email", u.Email, "master_password", DemoMasterPassword)
	return s.store.CachePut(ctx, key, "1")
}

func ptr(s string) *string { return &s }

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
