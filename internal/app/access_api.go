package app

import (
	"context"
	"net/http"
	"time"
)

func (a *App) accessAPI(w http.ResponseWriter, r *http.Request) {
	m := a.engine.access
	if r.URL.Path == "/api/access/state" && r.Method == "GET" {
		respond(w, 200, map[string]any{"ok": true, "access": m.State()})
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "仅支持 POST")
		return
	}
	var q struct {
		IP      string `json:"ip"`
		Seconds int    `json:"seconds"`
		ID      string `json:"id"`
	}
	if !decode(w, r, &q) {
		return
	}
	var err error
	switch r.URL.Path {
	case "/api/access/ban":
		err = m.Ban(q.IP, q.Seconds)
	case "/api/access/unban":
		err = m.Unban(q.IP, false)
	case "/api/access/clear-auto":
		err = m.Unban("", true)
	case "/api/access/update":
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		err = m.Update(ctx, q.ID)
	default:
		fail(w, 404, "接口不存在")
		return
	}
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	respond(w, 200, map[string]any{"ok": true, "access": m.State()})
}
