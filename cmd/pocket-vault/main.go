// Command pocket-vault is a password manager for your own server that the
// Bitwarden apps can use: the browser extension, the phone and desktop
// apps and the CLI. One binary, one SQLite file.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/config"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/server"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
	"github.com/abjelosevic88/pocket-homelab-vault/web"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println("pocket-vault", version)
			return
		case "backup":
			runBackup(os.Args[2:])
			return
		case "reset-password":
			runResetPassword(os.Args[2:])
			return
		case "import-vaultwarden":
			runImportVaultwarden(os.Args[2:])
			return
		case "help", "--help", "-h":
			fmt.Println(`pocket-vault — your passwords, on your server, in the Bitwarden apps

Usage:
  pocket-vault                     start the server (default)
  pocket-vault backup [-o FILE]    write a consistent SQLite backup
  pocket-vault reset-password [-email USER] [-password NEW]
                                   set a user's Pocket Vault sign-in password (not the master password)
  pocket-vault import-vaultwarden -dir VW_DATA [-replace] [-email ONE] [-no-key]
                                   copy accounts, items, folders and signed-in apps from a
                                   Vaultwarden data folder (db.sqlite3 + rsa_key.pem); stop
                                   Pocket Vault first
  pocket-vault version             print version

Configuration is read from environment variables, see docs/configuration.md.`)
			return
		}
	}
	serve()
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

func mustLoad() (*config.Config, *slog.Logger, *store.Store) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	log := newLogger(cfg)
	st, err := store.Open(cfg.DBPath, log)
	if err != nil {
		log.Error("open database", "path", cfg.DBPath, "err", err)
		os.Exit(1)
	}
	return cfg, log, st
}

func serve() {
	server.Version = version
	cfg, log, st := mustLoad()
	defer st.Close()

	var webFS fs.FS
	if sub, err := fs.Sub(web.Dist, "dist"); err == nil {
		if f, err := sub.Open("index.html"); err == nil {
			f.Close()
			webFS = sub
		}
	}
	if webFS == nil {
		log.Warn("web UI not embedded; API only (run `make web` before building)")
	}

	srv := server.New(cfg, st, log, webFS)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := srv.Bootstrap(ctx); err != nil {
		log.Error("bootstrap", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		log.Info("pocket-vault started", "version", version, "addr", cfg.Addr(), "base_url", cfg.BaseURL, "db", cfg.DBPath, "auth_mode", cfg.AuthMode)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, c2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer c2()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func runBackup(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	out := fs.String("o", "", "output file (default: DATA_DIR/backups/pocket-vault-<timestamp>.db)")
	_ = fs.Parse(args)
	cfg, log, st := mustLoad()
	defer st.Close()
	dst := *out
	if dst == "" {
		_ = os.MkdirAll(cfg.DataDir+"/backups", 0o755)
		dst = fmt.Sprintf("%s/backups/pocket-vault-%s.db", cfg.DataDir, time.Now().Format("20060102-150405"))
	}
	if err := st.Backup(context.Background(), dst); err != nil {
		log.Error("backup failed", "err", err)
		os.Exit(1)
	}
	fmt.Println(dst)
}

func runResetPassword(args []string) {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	email := fs.String("email", "", "user email (default: the first user)")
	password := fs.String("password", "", "new password (default: generate a random one)")
	_ = fs.Parse(args)
	_, log, st := mustLoad()
	defer st.Close()
	ctx := context.Background()
	var u *store.User
	var err error
	if *email != "" {
		u, err = st.GetUserByEmail(ctx, *email)
	} else {
		var users []store.User
		users, err = st.ListUsers(ctx)
		if err == nil && len(users) > 0 {
			u = &users[0]
		} else if err == nil {
			err = errors.New("no users found")
		}
	}
	if err != nil {
		log.Error("reset-password: user lookup failed", "err", err)
		os.Exit(1)
	}
	pw := *password
	if pw == "" {
		const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			log.Error("reset-password: random", "err", err)
			os.Exit(1)
		}
		for i := range b {
			b[i] = alphabet[int(b[i])%len(alphabet)]
		}
		pw = string(b)
	}
	if len(pw) < 8 {
		log.Error("reset-password: password must be at least 8 characters")
		os.Exit(1)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Error("reset-password: hash", "err", err)
		os.Exit(1)
	}
	u.PasswordHash = string(h)
	if err := st.UpdateUser(ctx, u); err != nil {
		log.Error("reset-password: save", "err", err)
		os.Exit(1)
	}
	if *password == "" {
		fmt.Printf("Password for %s reset.\nTemporary password: %s\nChange it under Settings → Profile after logging in.\n", u.Email, pw)
	} else {
		fmt.Printf("Password for %s reset.\n", u.Email)
	}
}

func runImportVaultwarden(args []string) {
	fs := flag.NewFlagSet("import-vaultwarden", flag.ExitOnError)
	dir := fs.String("dir", "", "Vaultwarden's data folder (holds db.sqlite3 and rsa_key.pem)")
	replace := fs.Bool("replace", false, "replace vaults that already exist here")
	email := fs.String("email", "", "import only this account")
	noKey := fs.Bool("no-key", false, "don't take rsa_key.pem (the apps then sign in again)")
	_ = fs.Parse(args)
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "import-vaultwarden: -dir is required")
		os.Exit(2)
	}
	server.Version = version
	cfg, log, st := mustLoad()
	defer st.Close()
	srv := server.New(cfg, st, log, nil)
	ctx := context.Background()
	if err := srv.PrepareCLI(ctx); err != nil {
		log.Error("import-vaultwarden", "err", err)
		os.Exit(1)
	}
	opt := server.VWOptions{Replace: *replace, Only: *email}
	if !*noKey {
		if b, err := os.ReadFile(*dir + "/rsa_key.pem"); err == nil {
			opt.KeyPEM = b
		} else {
			fmt.Println("No rsa_key.pem found: the apps will have to sign in again.")
		}
	}
	rep, err := srv.ImportVaultwarden(ctx, *dir+"/db.sqlite3", opt)
	if err != nil {
		log.Error("import-vaultwarden", "err", err)
		os.Exit(1)
	}
	for _, a := range rep.Accounts {
		line := fmt.Sprintf("%-40s %-9s", a.Email, a.Status)
		if a.Status != "skipped" {
			line += fmt.Sprintf(" %d items, %d folders, %d apps", a.Items, a.Folders, a.Devices)
			if a.TwoFactor {
				line += ", two-step login on"
			}
		} else {
			line += " " + a.Reason
		}
		fmt.Println(line)
	}
	if rep.KeyKept {
		fmt.Println("Kept Vaultwarden's signing key: signed-in apps stay signed in once the address points here.")
	}
	for _, n := range rep.Notes {
		fmt.Println("Note:", n)
	}
}
