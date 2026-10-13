package app

import (
	"github.com/gorilla/websocket"
	"io"
	"linknest/internal/access"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccessProxy404AndSpoofedForwarding(t *testing.T) {
	s, e := newStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	eng := newEngine(s, func(string, string) {}, newFirewall(false))
	defer eng.close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer upstream.Close()
	c := s.snapshot()
	c.Access.AutoBan.Enabled = true
	c.Access.AutoBan.IgnorePrivate = false
	c.Access.AutoBan.Threshold = 2
	c.Rules = []Rule{{ID: "access-test", Name: "access", Kind: "web", Enabled: true, Listen: "127.0.0.1:0", Routes: []WebRoute{{ID: "route", Name: "route", Enabled: true, Domains: []string{"*"}, Target: upstream.URL}}}}
	// Get a concrete free port; production validation prohibits port zero.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	c.Rules[0].Listen = l.Addr().String()
	l.Close()
	if e = s.save(c); e != nil {
		t.Fatal(e)
	}
	eng.apply(c)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for _, want := range []int{404, 404, 403} {
		r, _ := http.NewRequest("GET", "http://"+c.Rules[0].Listen+"/absent", nil)
		r.Header.Set("X-Forwarded-For", "8.8.8.8")
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("got %d want %d", res.StatusCode, want)
		}
	}
	st := eng.access.State()
	if len(st.Bans) != 1 || st.Bans[0].IP != "127.0.0.1" {
		t.Fatal("trusted spoofed XFF", st)
	}
}
func TestAccessProxyPreservesWebSocket(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := up.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		kind, b, e := c.ReadMessage()
		if e == nil {
			_ = c.WriteMessage(kind, b)
		}
	}))
	defer backend.Close()
	s, _ := newStore(t.TempDir())
	eng := newEngine(s, func(string, string) {}, newFirewall(false))
	defer eng.close()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	c := s.snapshot()
	c.Access = access.DefaultConfig()
	c.Access.AutoBan.Enabled = true
	c.Rules = []Rule{{ID: "ws", Name: "ws", Kind: "web", Enabled: true, Listen: addr, Routes: []WebRoute{{ID: "route", Name: "route", Enabled: true, Target: backend.URL}}}}
	eng.apply(c)
	ws, res, e := websocket.DefaultDialer.Dial("ws://"+addr+"/", nil)
	if e != nil {
		t.Fatal(e, res)
	}
	defer ws.Close()
	_ = ws.WriteMessage(websocket.TextMessage, []byte("hello"))
	_, b, e := ws.ReadMessage()
	if e != nil || string(b) != "hello" {
		t.Fatal("WebSocket broken", e, string(b))
	}
}
func TestAccessAPIAuthenticationAndCSRF(t *testing.T) {
	a, e := newApp(t.TempDir(), "127.0.0.1:17880", false)
	if e != nil {
		t.Fatal(e)
	}
	defer a.engine.close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/access/state", nil)
	a.handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("unauthed access allowed")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/access/clear-auto", nil)
	a.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
}
