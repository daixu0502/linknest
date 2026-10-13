package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestVersionedResources(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/", "/index.html"} {
		w := request(a, "GET", path, nil, nil)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-LinkNest-Version") != version || strings.Contains(w.Body.String(), "__VERSION__") || !strings.Contains(w.Body.String(), "/icons.js?v="+version) {
			t.Fatal(path, w.Code, w.Header())
		}
		w = request(a, "HEAD", path, nil, nil)
		if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("HEAD failed", path)
		}
	}
	for _, path := range []string{"/app.js", "/layout-fixes.css", "/icons.js?v=" + version} {
		w := request(a, "GET", path, nil, nil)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
			t.Fatal(path, w.Code, w.Header())
		}
	}
}

func TestWOLPortalStatusProtection(t *testing.T) {
	s := testStore(t)
	s.mu.Lock()
	s.cfg.Devices = []Device{{ID: "test-device", Name: "Private device", IP: "192.0.2.10"}}
	s.mu.Unlock()
	p := newPortal(s, quiet)
	route := WebRoute{ID: "wol", Name: "test", Backend: "wol", PublicAccess: true}
	run := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://wol.example:18080"+path, strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		p.serve(route, w, r)
		return w
	}
	w := run("GET", "/", "", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "网络唤醒") || !strings.Contains(w.Body.String(), "wol-dashboard") || !strings.Contains(w.Body.String(), "/portal.js?v="+version) {
		t.Fatal(w.Body.String())
	}
	ck := w.Result().Cookies()[0]
	body := "csrf=" + url.QueryEscape(ck.Value)
	endpoint, origin := "/__linknest/devices/check", "http://wol.example:18080"
	for _, bad := range []string{"", "null", "http://evil.example", "https://wol.example:18080"} {
		if run("POST", endpoint, body, bad, ck).Code != 403 {
			t.Fatal("origin bypass", bad)
		}
	}
	if run("POST", endpoint, "", origin, ck).Code != 403 || run("POST", endpoint, body, origin, nil).Code != 403 {
		t.Fatal("auth/CSRF bypass")
	}
	if run("GET", endpoint, "", "", ck).Code != 404 {
		t.Fatal("GET status allowed")
	}
	route.Backend = "bookmarks"
	if run("POST", endpoint, body, origin, ck).Code != 404 {
		t.Fatal("bookmarks can probe")
	}
	route.Backend = "wol"
	route.PublicAccess = false
	route.AccessPassword = "protected"
	w = run("GET", "/", "", "", nil)
	if strings.Contains(w.Body.String(), "192.0.2.10") || strings.Contains(w.Body.String(), "Private device") {
		t.Fatal("private device leaked")
	}
	if run("POST", endpoint, body, origin, ck).Code != 403 {
		t.Fatal("public token bypasses private route")
	}
	// Authenticate without testing passwords again; no wake packets are sent.
	ck.Value = "test-session"
	p.sessions[ck.Value] = portalSession{Route: route.ID, Hash: route.AccessPassword, Expires: time.Now().Add(time.Minute)}
	s.mu.Lock()
	s.cfg.Devices = []Device{{ID: "unconfigured"}}
	s.mu.Unlock()
	w = run("POST", endpoint, "csrf="+ck.Value, origin, ck)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "unconfigured") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestWOLStatusCacheAndConcurrency(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	s := testStore(t)
	s.mu.Lock()
	s.cfg.Devices = []Device{{ID: "online", IP: "127.0.0.1", CheckPort: listener.Addr().(*net.TCPAddr).Port}, {ID: "unconfigured"}}
	s.mu.Unlock()
	p := newPortal(s, quiet)
	run := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		p.checkDevices(w, httptest.NewRequest("POST", "/", nil))
		return w
	}
	w := run()
	var result struct {
		Devices []DeviceStatus `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(result.Devices) != 2 || result.Devices[0].State != "online" || result.Devices[1].State != "unconfigured" {
		t.Fatal(w.Body.String())
	}
	at := p.probedAt
	if run().Body.String() != w.Body.String() || !p.probedAt.Equal(at) {
		t.Fatal("cached result not reused")
	}
	s.mu.Lock()
	s.cfg.Devices[0].IP = ""
	s.mu.Unlock()
	w = run()
	if p.probedDevices[0].IP != "" || strings.Contains(w.Body.String(), `"state":"online"`) {
		t.Fatal("changed configuration reused stale results")
	}
	p.probeMu.Lock()
	if run().Code != 429 {
		t.Fatal("concurrent batch allowed")
	}
	p.probeMu.Unlock()
	p.probedAt = time.Time{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.checkDevices(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil).WithContext(ctx))
	if !p.probedAt.IsZero() {
		t.Fatal("cancelled result cached")
	}
}
