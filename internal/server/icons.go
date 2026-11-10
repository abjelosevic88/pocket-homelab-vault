package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---- website icons: /icons/<domain>/icon.png ----
//
// The apps show a site's icon next to each login and ask the server for it.
// Icons are fetched from the site itself (or a public icon service, see
// ICON_SERVICE), only from public addresses, and kept on disk.

var validDomain = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// a 1×1 transparent PNG for "no icon"
var blankPNG = []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00,
	0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82}

type iconFetcher struct {
	dir     string
	service string
	ttl     time.Duration
	client  *http.Client
	ua      string
	mu      sync.Mutex
	busy    map[string]chan struct{}
}

func newIconFetcher(dir, service, ua string, ttl time.Duration) *iconFetcher {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: publicOnly}
	tr := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second}
	return &iconFetcher{dir: dir, service: service, ttl: ttl, ua: ua, busy: map[string]chan struct{}{},
		client: &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		}}}
}

// publicOnly refuses connections to the box's own network (no fetching
// router pages or other apps through a "website icon").
func publicOnly(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() || isCGNAT(ip) {
		return errors.New("not a public address")
	}
	return nil
}

func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64
}

func (s *Server) handleIcon(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSuffix(chiParam(r, "domain"), "."))
	if s.icons == nil || s.cfg.IconService == "off" || !validDomain.MatchString(domain) || len(domain) > 253 {
		serveIcon(w, blankPNG, "image/png", time.Hour)
		return
	}
	switch s.cfg.IconService {
	case "duckduckgo":
		http.Redirect(w, r, "https://icons.duckduckgo.com/ip3/"+url.PathEscape(domain)+".ico", http.StatusFound)
		return
	case "google":
		http.Redirect(w, r, "https://www.google.com/s2/favicons?domain="+url.QueryEscape(domain)+"&sz=32", http.StatusFound)
		return
	}
	body, ctype, ok := s.icons.get(r.Context(), domain)
	if !ok {
		serveIcon(w, blankPNG, "image/png", 6*time.Hour)
		return
	}
	serveIcon(w, body, ctype, 7*24*time.Hour)
}

func serveIcon(w http.ResponseWriter, b []byte, ctype string, maxAge time.Duration) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(maxAge.Seconds())))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	_, _ = w.Write(b)
}

// get returns a cached icon or fetches it once (concurrent asks wait).
func (f *iconFetcher) get(ctx context.Context, domain string) ([]byte, string, bool) {
	sum := sha256.Sum256([]byte(domain))
	name := hex.EncodeToString(sum[:12])
	path := filepath.Join(f.dir, name)
	if b, ctype, ok := f.cached(path); ok {
		return b, ctype, len(b) > 0
	}
	f.mu.Lock()
	if ch, ok := f.busy[domain]; ok {
		f.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, "", false
		}
		b, ctype, _ := f.cached(path)
		return b, ctype, len(b) > 0
	}
	ch := make(chan struct{})
	f.busy[domain] = ch
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.busy, domain)
		f.mu.Unlock()
		close(ch)
	}()
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	b, ctype := f.fetch(fctx, domain)
	_ = os.MkdirAll(f.dir, 0o755)
	if len(b) == 0 {
		_ = os.WriteFile(path+".miss", nil, 0o644) // remembered for a few days
		return nil, "", false
	}
	_ = os.WriteFile(path, append([]byte(ctype+"\n"), b...), 0o644)
	_ = os.Remove(path + ".miss")
	return b, ctype, true
}

func (f *iconFetcher) cached(path string) ([]byte, string, bool) {
	if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < f.ttl {
		raw, err := os.ReadFile(path)
		if err == nil {
			if i := bytes.IndexByte(raw, '\n'); i > 0 {
				return raw[i+1:], string(raw[:i]), true
			}
		}
	}
	if st, err := os.Stat(path + ".miss"); err == nil && time.Since(st.ModTime()) < 3*24*time.Hour {
		return nil, "", true
	}
	return nil, "", false
}

var iconLink = regexp.MustCompile(`(?is)<link\b[^>]*>`)
var attrRe = regexp.MustCompile(`(?is)\b(rel|href|sizes)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)

// fetch reads the site's home page for its icon links, then tries them
// (largest first) and /favicon.ico.
func (f *iconFetcher) fetch(ctx context.Context, domain string) ([]byte, string) {
	var candidates []string
	base := "https://" + domain + "/"
	if page, final := f.download(ctx, base, 512<<10, false); page != nil {
		bu, _ := url.Parse(final)
		if bu == nil {
			bu, _ = url.Parse(base)
		}
		type cand struct {
			href string
			size int
		}
		var cs []cand
		for _, tag := range iconLink.FindAllString(string(page), 60) {
			attrs := map[string]string{}
			for _, m := range attrRe.FindAllStringSubmatch(tag, -1) {
				v := m[3] + m[4] + m[5]
				attrs[strings.ToLower(m[1])] = v
			}
			rel := strings.ToLower(attrs["rel"])
			if !strings.Contains(rel, "icon") || attrs["href"] == "" || strings.Contains(rel, "mask") {
				continue
			}
			u, err := bu.Parse(strings.TrimSpace(attrs["href"]))
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
				continue
			}
			size := 16
			if sz := attrs["sizes"]; sz != "" {
				var a, b int
				if _, err := fmt.Sscanf(strings.ToLower(sz), "%dx%d", &a, &b); err == nil {
					size = a
				}
			}
			if strings.Contains(rel, "apple-touch") && size == 16 {
				size = 180
			}
			cs = append(cs, cand{u.String(), size})
		}
		// prefer something near 32–192 px
		score := func(n int) int {
			if n >= 32 && n <= 192 {
				return 1000 - n
			}
			if n > 192 {
				return 500 - n/10
			}
			return n
		}
		for i := range cs {
			for j := i + 1; j < len(cs); j++ {
				if score(cs[j].size) > score(cs[i].size) {
					cs[i], cs[j] = cs[j], cs[i]
				}
			}
		}
		for _, c := range cs {
			candidates = append(candidates, c.href)
		}
		if bu != nil {
			candidates = append(candidates, bu.Scheme+"://"+bu.Host+"/favicon.ico")
		}
	}
	candidates = append(candidates, base+"favicon.ico")
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c] || len(seen) > 6 {
			continue
		}
		seen[c] = true
		if b, _ := f.download(ctx, c, 256<<10, true); len(b) > 0 {
			if ct := iconType(b); ct != "" {
				return b, ct
			}
		}
	}
	return nil, ""
}

// download GETs a URL (up to max bytes); for images it must not be HTML.
func (f *iconFetcher) download(ctx context.Context, u string, max int64, image bool) ([]byte, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("User-Agent", f.ua)
	req.Header.Set("Accept", "text/html,image/*;q=0.9,*/*;q=0.5")
	res, err := f.client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, ""
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, ""
	}
	return b, res.Request.URL.String()
}

// iconType recognises the image formats served as icons (SVG is not: it
// can carry scripts).
func iconType(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "image/png"
	case bytes.HasPrefix(b, []byte{0, 0, 1, 0}):
		return "image/x-icon"
	case bytes.HasPrefix(b, []byte("GIF8")):
		return "image/gif"
	case bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}):
		return "image/jpeg"
	case len(b) > 12 && bytes.Equal(b[0:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return "image/webp"
	}
	return ""
}
