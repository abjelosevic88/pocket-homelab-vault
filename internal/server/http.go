package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	core "github.com/abjelosevic88/pocket-homelab-core/sdk"
	"github.com/abjelosevic88/pocket-homelab-vault/internal/store"
)

// Router builds the chi router: the Bitwarden-compatible API the apps use
// (/identity, /api, /notifications, /icons), the Pocket API of this app
// (/api/v1) and the web vault.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	if s.cfg.TrustProxy {
		r.Use(middleware.RealIP)
	}
	r.Use(middleware.RequestID)
	r.Use(s.logging)
	r.Use(middleware.Recoverer)
	r.Use(s.securityHeaders)

	// live sync (websockets: no compression, no timeout)
	r.Get("/notifications/hub", s.handleHub)
	r.Post("/notifications/hub/negotiate", s.handleHubNegotiate)
	r.Get("/notifications/anonymous-hub", s.handleAnonymousHub)
	r.Post("/notifications/anonymous-hub/negotiate", s.handleHubNegotiate)

	r.Group(func(r chi.Router) {
		r.Use(middleware.Compress(5))
		r.Use(s.cors)
		r.Get("/healthz", s.handleHealth)
		r.Get("/readyz", s.handleReady)
		if s.cfg.MetricsEnabled {
			r.Get("/metrics", s.handleMetrics)
		}
		r.Get("/icons/{domain}/icon.png", s.handleIcon)
		r.Post("/events/collect", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

		r.Route("/identity", func(r chi.Router) {
			r.Use(middleware.Timeout(60 * time.Second))
			r.Post("/connect/token", s.handleToken)
			r.Post("/accounts/prelogin", s.handlePrelogin)
			r.Post("/accounts/prelogin/password", s.handlePrelogin)
			r.Post("/accounts/register", s.handleRegister)
			r.Post("/accounts/register/send-verification-email", s.handleRegister)
			r.Post("/accounts/register/finish", s.handleRegister)
			r.Get("/sso/prevalidate", func(w http.ResponseWriter, r *http.Request) {
				bwErr(w, http.StatusBadRequest, "Single sign-on isn't available here.")
			})
		})

		r.Route("/api", func(r chi.Router) {
			r.Route("/v1", s.pocketRoutes)
			r.Group(func(r chi.Router) {
				r.Use(middleware.Timeout(120 * time.Second))
				s.bwRoutes(r)
			})
			r.NotFound(func(w http.ResponseWriter, r *http.Request) {
				bwErr(w, http.StatusNotFound, "The requested resource could not be found.")
			})
		})

		r.NotFound(s.handleSPA)
	})
	return r
}

// pocketRoutes is this app's own API (sign-in to Pocket Vault, settings,
// the vault's Pocket side).
func (s *Server) pocketRoutes(r chi.Router) {
	r.Use(middleware.Timeout(120 * time.Second))
	r.Get("/health", s.handleHealth)
	r.Post("/auth/login", s.handleLogin)
	r.Post("/auth/setup", s.handleSetup)
	r.Get("/auth/status", s.handleAuthStatus)
	r.Get("/auth/oidc/start", s.handleOIDCStart)
	r.Get("/auth/oidc/callback", s.handleOIDCCallback)

	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Post("/auth/logout", s.handleLogout)
		r.Get("/auth/me", s.handleMe)
		r.Put("/auth/me", s.handleUpdateMe)

		// the vault, Pocket side
		r.Get("/vault/status", s.handleVaultStatus)
		r.Post("/vault/setup", s.handleVaultSetup)
		r.Delete("/vault", s.handleVaultDelete)
		r.Get("/vault/overview", s.handleVaultOverview)
		r.Get("/vault/activity", s.handleVaultActivity)
		r.Get("/vault/devices", s.handleVaultDevices)
		r.Delete("/vault/devices/{id}", s.handleVaultRemoveDevice)
		r.Post("/vault/sign-out-everywhere", s.handleVaultSignOutEverywhere)
		r.Put("/vault/health", s.handlePutVaultHealth)
		r.Get("/vault/reminders", s.handleListReminders)
		r.Post("/vault/reminders", s.handleCreateReminder)
		r.Delete("/vault/reminders/{id}", s.handleDeleteReminder)
		r.Post("/vault/import/vaultwarden", s.handleImportVaultwarden)

		r.Post("/integrations/test", s.handleIntegrationTest)
		r.Post("/notify/test", s.handleNotifyTest)

		r.Get("/users", s.handleListUsers)
		r.Post("/users", s.handleCreateUser)
		r.Put("/users/{id}", s.handleUpdateUser)
		r.Delete("/users/{id}", s.handleDeleteUser)

		r.Get("/settings", s.handleGetSettings)
		r.Put("/settings", s.handlePutSettings)
		r.Get("/settings/system", s.handleSystemInfo)

		r.Get("/tokens", s.handleListTokens)
		r.Post("/tokens", s.handleCreateToken)
		r.Delete("/tokens/{id}", s.handleDeleteToken)

		r.Get("/backup", s.handleBackup)
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "not found") })
}

// securityHeaders are set on every answer (the web vault holds secrets:
// no framing, no sniffing, no referrer to other sites).
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if !strings.HasPrefix(r.URL.Path, "/notifications/") {
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("X-Robots-Tag", "noindex, nofollow")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		}
		next.ServeHTTP(w, r)
	})
}

// cors answers the apps' preflight requests. Like Vaultwarden, only this
// server's own origin and the desktop/Safari app origins are allowed; the
// browser extensions don't need CORS.
func (s *Server) cors(next http.Handler) http.Handler {
	own := s.bwOrigin()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (origin == own || origin == "file://" || origin == "bw-desktop-file://bundle") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
			w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- helpers ----------

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.requests.Add(1)
		if ww.Status() >= 500 {
			s.errors.Add(1)
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			return
		}
		s.log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", ww.Status(), "dur", time.Since(start).String(), "ip", r.RemoteAddr)
	})
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func (s *Server) fail(w http.ResponseWriter, err error, context string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
		return
	case errors.Is(err, store.ErrConflict), errors.Is(err, core.ErrOperationConflict):
		writeErr(w, http.StatusConflict, "already exists")
		return
	}
	s.log.Error(context, "err", err)
	writeErr(w, http.StatusInternalServerError, context+": "+err.Error())
}

func (s *Server) readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(nil, r.Body, s.cfg.MaxBodyBytes))
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 32<<20))
	return dec.Decode(v)
}

// decodeKeys decodes JSON into v and also reports which top-level keys were
// present, so PUT handlers can tell "not sent" from "sent empty".
func decodeKeys(r *http.Request, v any) (map[string]bool, error) {
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	keys := make(map[string]bool, len(raw))
	for k := range raw {
		keys[k] = true
	}
	return keys, json.Unmarshal(b, v)
}

func idParam(r *http.Request, name string) int64 {
	n, _ := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	return n
}

func queryInt(r *http.Request, name string) int {
	n, _ := strconv.Atoi(r.URL.Query().Get(name))
	return n
}

func queryBool(r *http.Request, name string) bool {
	v := strings.ToLower(r.URL.Query().Get(name))
	return v == "1" || v == "true" || v == "yes"
}

func validDate(s string) bool {
	if s == "" {
		return true
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// dateRange reads ?from&to (defaults: the last n days up to today).
func dateRange(r *http.Request, days int) (string, string) {
	to := r.URL.Query().Get("to")
	from := r.URL.Query().Get("from")
	if to == "" || !validDate(to) {
		to = store.Today()
	}
	if from == "" || !validDate(from) {
		from = store.AddDays(to, -(days - 1))
	}
	if from > to {
		from, to = to, from
	}
	return from, to
}

// ---------- health / metrics ----------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"core_outbox": s.coreOutboxHealth(r.Context()), "status": "ok", "version": Version, "uptime": time.Since(s.started).Round(time.Second).String()})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DB.PingContext(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	counts := s.store.Counts(ctx)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP pocket_vault_info Build info.\n# TYPE pocket_vault_info gauge\npocket_vault_info{version=%q} 1\n", Version)
	fmt.Fprintf(w, "# HELP pocket_vault_uptime_seconds Process uptime.\n# TYPE pocket_vault_uptime_seconds gauge\npocket_vault_uptime_seconds %d\n", int(time.Since(s.started).Seconds()))
	fmt.Fprintf(w, "# HELP pocket_vault_http_requests_total HTTP requests served.\n# TYPE pocket_vault_http_requests_total counter\npocket_vault_http_requests_total %d\n", s.requests.Load())
	fmt.Fprintf(w, "# HELP pocket_vault_http_errors_total HTTP 5xx responses.\n# TYPE pocket_vault_http_errors_total counter\npocket_vault_http_errors_total %d\n", s.errors.Load())
	fmt.Fprintf(w, "# HELP pocket_vault_rows Rows per table.\n# TYPE pocket_vault_rows gauge\n")
	for k, v := range counts {
		fmt.Fprintf(w, "pocket_vault_rows{table=%q} %d\n", k, v)
	}
	fmt.Fprintf(w, "# HELP pocket_vault_live_apps Apps connected for live sync.\n# TYPE pocket_vault_live_apps gauge\npocket_vault_live_apps %d\n", s.bw.hub.count())
}

// ---------- static / SPA ----------

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/identity/") {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self' https://api.pwnedpasswords.com; base-uri 'self'; form-action 'self'; object-src 'none'")
	if s.webFS == nil {
		http.Error(w, "web UI not built (run `make web`)", http.StatusNotFound)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if f, err := s.webFS.Open(path); err == nil {
		f.Close()
		if strings.HasPrefix(path, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.FileServerFS(s.webFS).ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	r.URL.Path = "/"
	http.FileServerFS(s.webFS).ServeHTTP(w, r)
}
