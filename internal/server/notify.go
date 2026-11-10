package server

import (
	"context"
	"net/http"

	"github.com/abjelosevic88/pocket-homelab-vault/internal/notify"
)

// securityAlert tells a person about something that happened to their
// vault (a new sign-in, wrong tries, a security change), when they have a
// notification address and that kind switched on. It never says what is in
// the vault.
func (s *Server) securityAlert(ctx context.Context, uid int64, kind, title, body, priority string) {
	st, err := s.store.GetSettings(ctx, uid)
	if err != nil || st.NotifyURL == "" {
		return
	}
	switch kind {
	case "new_device":
		if !st.NotifyNewDevice {
			return
		}
	case "failed":
		if !st.NotifyFailed {
			return
		}
	default:
		if !st.NotifySecurity {
			return
		}
	}
	tags := []string{"closed_lock_with_key"}
	if priority == "warning" {
		tags = []string{"warning"}
	}
	msg := notify.Message{Title: title, Body: body, Priority: priority, Tags: tags, Link: s.cfg.BaseURL + "/activity"}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20e9)
		defer cancel()
		if err := notify.New(st.NotifyURL, st.NotifyFormat).Send(ctx, msg); err != nil {
			s.log.Warn("security alert not sent", "err", err)
		}
	}()
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st, _ := s.store.GetSettings(ctx, actorID(ctx))
	if st.NotifyURL == "" {
		writeErr(w, http.StatusBadRequest, "add a notification address first")
		return
	}
	n := notify.New(st.NotifyURL, st.NotifyFormat)
	if err := n.Send(ctx, notify.Message{Title: "Pocket Vault", Body: "Notifications work. New sign-ins and changes to your vault's security will arrive here.", Priority: "info", Tags: []string{"closed_lock_with_key"}}); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
