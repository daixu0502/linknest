package app

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestUsernameLoginAndMigration(t *testing.T) {
	for _, value := range []string{"", "bad\x1bname", "bad\x7fname", " admin "} {
		if validUsername(value) {
			t.Fatal("invalid username accepted")
		}
	}
	a := testApp(t)
	cookie := signIn(t, a)
	for _, user := range []string{"", "wrong@example.com"} {
		if w := request(a, "POST", "/api/login", map[string]string{"username": user, "password": "test-password-12345"}, nil); w.Code != 401 {
			t.Fatal("accepted missing/wrong username", w.Code)
		}
	}
	if w := request(a, "POST", "/api/password", map[string]string{"currentPassword": "test-password-12345", "newPassword": "changed-test-password"}, cookie); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if a.auth.Username != "admin" {
		t.Fatal("password change lost username")
	}
	if w := request(a, "POST", "/api/login", map[string]string{"username": "admin", "password": "changed-test-password"}, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	dir := t.TempDir()
	hash, _ := bcrypt.GenerateFromPassword([]byte("migration-test-password"), bcrypt.MinCost)
	b, _ := json.Marshal(authConfig{PasswordHash: string(hash)})
	if e := writeAtomic(filepath.Join(dir, "auth.json"), b); e != nil {
		t.Fatal(e)
	}
	t.Setenv("LINKNEST_INITIAL_USERNAME", "owner@example.com")
	migrated, e := newApp(dir, "127.0.0.1:17880", false)
	if e != nil {
		t.Fatal(e)
	}
	defer migrated.engine.close()
	defer migrated.dns.close()
	defer migrated.certs.close()
	if migrated.auth.Username != "owner@example.com" || migrated.auth.PasswordHash != string(hash) {
		t.Fatal("migration changed password or missed username")
	}
	disk, _ := os.ReadFile(filepath.Join(dir, "auth.json"))
	var auth authConfig
	json.Unmarshal(disk, &auth)
	if auth.Username != "owner@example.com" {
		t.Fatal("not persisted")
	}
	if w := request(migrated, "POST", "/api/login", map[string]string{"username": "OWNER@example.com", "password": "migration-test-password"}, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(migrated, "GET", "/api/health", nil, nil); strings.Contains(w.Body.String(), "owner@") {
		t.Fatal("unauthenticated username disclosure")
	}
}

func TestPortalPublicAccessProtection(t *testing.T) {
	s := testStore(t)
	c := s.snapshot()
	c.Bookmarks = []Bookmark{{ID: "site", Name: "Visible site", URL: "https://example.com", URLs: []string{"https://example.com", "https://alt.example.com"}, Description: "site description", Group: "Tools"}, {ID: "disabled", Name: "Hidden site", URL: "https://example.com", Disabled: true}}
	c.Rules = []Rule{{ID: "web", Name: "web", Listen: "127.0.0.1:18333", Kind: "web", Enabled: true, Routes: []WebRoute{{ID: "public", Name: "Public", Enabled: true, Backend: "bookmarks", PublicAccess: true, AccessPassword: "will-be-cleared"}}}}
	if e := s.save(c); e != nil {
		t.Fatal(e)
	}
	route := s.snapshot().Rules[0].Routes[0]
	if route.AccessPassword != "" {
		t.Fatal("public mode retained password")
	}
	p := newPortal(s, quiet)
	run := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://panel.example:18080"+path, strings.NewReader(body))
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
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Visible site") || strings.Contains(w.Body.String(), "Hidden site") || strings.Contains(w.Body.String(), ">退出<") || !strings.Contains(w.Body.String(), "入口 2") {
		t.Fatal(w.Body.String())
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("native forms may get null origin")
	}
	cookie := w.Result().Cookies()[0]
	if len(p.sessions) != 0 {
		t.Fatal("public traffic consumed login slots")
	}
	for _, path := range []string{"/api/state", "/api/config", "/api/terminal", "/__linknest/login"} {
		method := "GET"
		if path == "/__linknest/login" {
			method = "POST"
		}
		if w := run(method, path, "", "http://panel.example:18080", cookie); w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	route.Backend = "wol"
	for _, origin := range []string{"null", "http://evil.example", "https://panel.example:18080", ""} {
		if w := run("POST", "/__linknest/wake", "id=nonexistent&csrf="+url.QueryEscape(cookie.Value), origin, cookie); w.Code != 403 {
			t.Fatal("cross origin allowed", origin, w.Code)
		}
	}
	if w := run("POST", "/__linknest/wake", "id=nonexistent", "http://panel.example:18080", cookie); w.Code != 403 {
		t.Fatal("missing csrf allowed")
	}
	// Nonexistent device reaches 404 only after authentication and CSRF; no packet is sent.
	if w := run("POST", "/__linknest/wake", "id=nonexistent&csrf="+url.QueryEscape(cookie.Value), "http://panel.example:18080", cookie); w.Code != 404 {
		t.Fatal(w.Body.String())
	}
	if p.validPublicToken("other", cookie.Value, time.Now()) || p.validPublicToken(route.ID, cookie.Value, time.Now().Add(9*time.Hour)) || p.validPublicToken(route.ID, cookie.Value+"x", time.Now()) {
		t.Fatal("invalid anonymous token")
	}
	route.PublicAccess = false
	route.AccessPassword = ""
	if w := run("GET", "/", "", "", cookie); w.Code != 503 {
		t.Fatal("public token bypassed password mode")
	}
	c = s.snapshot()
	c.Rules[0].Routes[0].PublicAccess = false
	if s.save(c) == nil {
		t.Fatal("reenabling password without password accepted")
	}
}

func TestPortalOriginAndPrivateLogin(t *testing.T) {
	for _, tc := range []struct {
		origin, referer, site string
		tls, ok               bool
	}{
		{"https://panel.example:18080", "", "same-origin", true, true},
		{"null", "", "same-origin", true, false},
		{"https://panel.example:18080", "", "cross-site", true, false},
		{"", "https://panel.example:18080/", "", true, true},
		{"http://panel.example:18080", "", "", true, false},
		{"", "", "", false, false},
	} {
		r := httptest.NewRequest("POST", "http://panel.example:18080/", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Referer", tc.referer)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		if tc.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if portalOrigin(r) != tc.ok {
			t.Fatal(tc)
		}
	}
	s := testStore(t)
	p := newPortal(s, quiet)
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-portal-password"), bcrypt.MinCost)
	route := WebRoute{ID: "private", Name: "Private", Backend: "bookmarks", AccessPassword: string(hash)}
	r := httptest.NewRequest("POST", "https://panel.example:18080/__linknest/login", strings.NewReader("password=test-portal-password"))
	r.Header.Set("Origin", "https://panel.example:18080")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.serve(route, w, r)
	if w.Code != 303 || !w.Result().Cookies()[0].Secure {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestPanelConfigurationAndIPMatching(t *testing.T) {
	c := testStore(t).snapshot()
	c.Panel = PanelConfig{Groups: []string{"Tools"}, NetworkMode: "auto", InternalCIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}}
	c.Bookmarks = []Bookmark{{ID: "one", Name: "One", URL: "https://external.example", InternalURLs: []string{"http://10.0.0.2:5000"}, Group: "Tools", SameTab: true}}
	if e := validate(c, "127.0.0.1:17880"); e != nil {
		t.Fatal(e)
	}
	if g := panelGroups(c, "10.1.2.3:20000"); g[0].Links[0].URLs[0] != "http://10.0.0.2:5000" || g[0].Links[0].Target != "_self" {
		t.Fatal(g)
	}
	if g := panelGroups(c, "8.8.8.8:20000"); g[0].Links[0].URLs[0] != "https://external.example" {
		t.Fatal(g)
	}
	if !panelInternal(c.Panel, "[2001:db8::2]:2000") {
		t.Fatal("IPv6 CIDR")
	}
	c.Bookmarks[0].Icon = "javascript:alert(1)"
	if validatePanel(c) == nil {
		t.Fatal("script URL accepted")
	}
	c.Bookmarks[0].Icon = ""
	c.Panel.InternalCIDRs = []string{"10.0.0.1"}
	if validatePanel(c) == nil {
		t.Fatal("bad CIDR accepted")
	}
	r := Rule{ID: "web", Name: "Web", Kind: "web", Listen: "127.0.0.1:18000", Routes: []WebRoute{{ID: "ip", Name: "IP", Enabled: true, Domains: []string{"192.168.1.1", "[::1]"}, Backend: "bookmarks", PublicAccess: true}}}
	if e := validateWeb(r, func(string) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if matchRoute(r.Routes, "192.168.1.1:18000") == nil || matchRoute(r.Routes, "[::1]:18000") == nil || matchRoute(r.Routes, "not-configured.example") != nil {
		t.Fatal("IP/host matching")
	}
}
