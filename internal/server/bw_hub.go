package server

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/bw"
)

// ---- live sync: /notifications/hub ----
//
// The browser extension and the desktop app keep a websocket open (SignalR,
// MessagePack) and sync the moment something changes elsewhere. Phones
// sync when opened or pulled down.

type hub struct {
	mu    sync.Mutex
	conns map[string]map[*hubConn]bool // account uuid → connections
}

type hubConn struct {
	out chan []byte
}

func newHub() *hub { return &hub{conns: map[string]map[*hubConn]bool{}} }

func (h *hub) add(acct string, c *hubConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[acct] == nil {
		h.conns[acct] = map[*hubConn]bool{}
	}
	h.conns[acct][c] = true
}

func (h *hub) remove(acct string, c *hubConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.conns[acct], c)
	if len(h.conns[acct]) == 0 {
		delete(h.conns, acct)
	}
}

// send queues a frame for every open connection of a vault (dropped when a
// slow connection's queue is full; the app syncs on its next start anyway).
func (h *hub) send(acct string, frame []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.conns[acct] {
		select {
		case c.out <- frame:
		default:
		}
	}
}

// countFor is how many apps of one vault are connected right now.
func (h *hub) countFor(acct string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns[acct])
}

// count is how many apps are connected right now.
func (h *hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.conns {
		n += len(m)
	}
	return n
}

var signalRHandshake = []byte(`{"protocol":"messagepack","version":1}`)

func (s *Server) handleHubNegotiate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"connectionId": store64(), "connectionToken": store64(), "negotiateVersion": 1,
		"availableTransports": []any{map[string]any{"transport": "WebSockets", "transferFormats": []string{"Text", "Binary"}}}})
}

func store64() string { return strings.TrimRight(bw.RandomBase32(16), "=") }

// handleHub accepts an app's websocket (token in ?access_token= or the
// Authorization header) and streams updates for its vault.
func (s *Server) handleHub(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("access_token")
	if tok == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
	}
	sess, err := s.bwSessionFor(r.Context(), tok)
	if err != nil {
		http.Error(w, "Invalid claim", http.StatusUnauthorized)
		return
	}
	s.serveHub(w, r, sess.acct.UUID)
}

// handleAnonymousHub is the hub for "sign in with another device" — not
// offered here, but apps open it; keep it open and quiet.
func (s *Server) handleAnonymousHub(w http.ResponseWriter, r *http.Request) {
	s.serveHub(w, r, "")
}

func (s *Server) serveHub(w http.ResponseWriter, r *http.Request, acct string) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	ws.SetReadLimit(64 << 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &hubConn{out: make(chan []byte, 64)}
	if acct != "" {
		s.bw.hub.add(acct, c)
		defer s.bw.hub.remove(acct, c)
	}
	go func() {
		defer cancel()
		for {
			typ, msg, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if typ == websocket.MessageText {
				m := bytes.TrimRight(msg, "\x1e")
				if bytes.Equal(bytes.ReplaceAll(m, []byte(" "), nil), signalRHandshake) {
					select {
					case c.out <- []byte{'{', '}', 0x1e}:
					default:
					}
				}
			}
		}
	}()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			ws.Close(websocket.StatusNormalClosure, "")
			return
		case f := <-c.out:
			wctx, wc := context.WithTimeout(ctx, 10*time.Second)
			err := ws.Write(wctx, websocket.MessageBinary, f)
			wc()
			if err != nil {
				return
			}
		case <-ping.C:
			wctx, wc := context.WithTimeout(ctx, 10*time.Second)
			err := ws.Write(wctx, websocket.MessageBinary, bw.PingFrame())
			wc()
			if err != nil {
				return
			}
		}
	}
}
