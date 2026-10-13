package app

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sharedRule(id, host, addr, target string) Rule {
	return Rule{ID: id, Name: id, Kind: "web", Enabled: true, Listen: addr, Routes: []WebRoute{{ID: id + "-route", Name: id, Enabled: true, Domains: []string{host}, Target: target}}}
}
func TestSharedValidation(t *testing.T) {
	c := testStore(t).snapshot()
	a := sharedRule("a", "a.example.com", "127.0.0.1:18081", "http://192.0.2.1:80")
	b := sharedRule("b", "b.example.com", a.Listen, a.Routes[0].Target)
	c.Rules = []Rule{a, b}
	if err := validate(c, "127.0.0.1:17880"); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"a.example.com", "A.example.com"} {
		c.Rules[1].Routes[0].Domains = []string{domain}
		if validate(c, "127.0.0.1:17880") == nil {
			t.Fatal("duplicate accepted", domain)
		}
	}
	c.Rules[0].Routes[0].Domains = nil
	c.Rules[1].Routes[0].Domains = []string{"*"}
	if validate(c, "127.0.0.1:17880") == nil {
		t.Fatal("two defaults accepted")
	}
	c.Rules[1].Enabled = false
	if err := validate(c, "127.0.0.1:17880"); err != nil {
		t.Fatal("disabled owner blocks port", err)
	}
	for _, kind := range []string{"tcp", "tcpudp"} {
		c.Rules = []Rule{a, {ID: "f", Name: "forward", Kind: kind, Enabled: true, Listen: a.Listen, Target: "192.0.2.1:80"}}
		if validate(c, "127.0.0.1:17880") == nil {
			t.Fatal("TCP collision accepted", kind)
		}
	}
	c.Rules[1].Kind = "udp"
	if err := validate(c, "127.0.0.1:17880"); err != nil {
		t.Fatal("independent UDP blocked", err)
	}
	c.Rules = []Rule{a, b}
	c.Rules[1].Listen = "0.0.0.0:18081"
	if validate(c, "127.0.0.1:17880") == nil {
		t.Fatal("bind widened")
	}
	a.OpenFirewall = false
	b.OpenFirewall = true
	merged := sharedFirewallRules([]Rule{a, b})
	if len(merged) != 1 || !merged[0].OpenFirewall {
		t.Fatal(merged)
	}
}

func TestSharedLifecycleAndTLS(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.URL.Path) }))
	defer up.Close()
	s := testStore(t)
	e := newEngine(s, quiet, newFirewall(false))
	defer e.close()
	addr := freePort(t)
	c := s.snapshot()
	a := sharedRule("a", "a.example.com", addr, up.URL+"/a")
	b := sharedRule("b", "*.example.com", addr, up.URL+"/b")
	c.Rules = []Rule{a}
	e.apply(c)
	listener := e.webGroups[webListenKey(a)]
	get := func(host string, secure bool, sni string) (int, string, *http.Response) {
		t.Helper()
		scheme := "http"
		tr := &http.Transport{}
		if secure {
			scheme = "https"
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: sni}
		} // Local generated certificates only; peer DER checked below.
		defer tr.CloseIdleConnections()
		client := &http.Client{Timeout: 3 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		q, _ := http.NewRequest("GET", scheme+"://"+addr+"/", nil)
		q.Host = host
		res, err := client.Do(q)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body), res
	}
	c.Rules = append(c.Rules, b)
	e.apply(c)
	if listener != e.webGroups[webListenKey(a)] || len(e.webGroups) != 1 {
		t.Fatal("listener restarted")
	}
	for host, want := range map[string]string{"a.example.com": "/a/", "b.example.com": "/b/"} {
		if code, body, _ := get(host, false, ""); code != 200 || body != want {
			t.Fatal(host, code, body)
		}
	}
	if code, _, _ := get("unknown.invalid", false, ""); code != 421 {
		t.Fatal(code)
	}
	cm := newCerts(s, quiet)
	defer cm.close()
	cert1, key1 := testPair(t)
	cert2, key2 := testPair(t)
	if err := cm.importPair("one", cert1, key1); err != nil {
		t.Fatal(err)
	}
	if err := cm.importPair("two", cert2, key2); err != nil {
		t.Fatal(err)
	}
	c.Rules[0].TLS = true
	c.Rules[0].RedirectHTTP = true
	c.Rules[0].Certificate = "one"
	c.Rules[1].TLS = true
	c.Rules[1].Certificate = "two"
	e.apply(c)
	if listener != e.webGroups[webListenKey(a)] {
		t.Fatal("TLS add restarted listener")
	}
	if code, _, res := get("a.example.com", false, ""); code != 307 || res.Header.Get("Location") != "https://a.example.com/" {
		t.Fatal(code)
	}
	if code, _, _ := get("b.example.com", false, ""); code != 400 {
		t.Fatal(code)
	}
	pair1, _ := tls.X509KeyPair(cert1, key1)
	pair2, _ := tls.X509KeyPair(cert2, key2)
	for host, want := range map[string][]byte{"a.example.com": pair1.Certificate[0], "b.example.com": pair2.Certificate[0]} {
		code, _, res := get(host, true, host)
		if code != 200 || !bytes.Equal(res.TLS.PeerCertificates[0].Raw, want) {
			t.Fatal("wrong SNI certificate", host)
		}
	}
	if code, _, _ := get("b.example.com", true, "a.example.com"); code != 421 {
		t.Fatal("cross-owner TLS accepted")
	}
	os.Remove(filepath.Join(s.dir, "certificates", "one.pem"))
	e.apply(c)
	if e.rules["a"].status.State != "error" {
		t.Fatal("invalid cert status")
	}
	if code, _, _ := get("a.example.com", false, ""); code != 503 {
		t.Fatal("invalid owner fell into wildcard", code)
	}
	if code, _, _ := get("b.example.com", true, "b.example.com"); code != 200 {
		t.Fatal("healthy owner affected")
	}
	c.Rules[0].Enabled = false
	e.apply(c)
	if listener != e.webGroups[webListenKey(a)] {
		t.Fatal("disable closed other listener")
	}
	c.Rules = c.Rules[1:]
	e.apply(c)
	if code, _, _ := get("b.example.com", true, "b.example.com"); code != 200 {
		t.Fatal(code)
	}
	c.Rules = nil
	e.apply(c)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal("last owner did not release port", err)
	}
	ln.Close()
}

func TestProtocolSeparatedAdminCookies(t *testing.T) {
	a := testApp(t)
	signIn(t, a)
	login := func(secure bool) *http.Cookie {
		body, _ := json.Marshal(map[string]string{"username": "admin", "password": "test-password-12345"})
		q := httptest.NewRequest("POST", "http://localhost/api/login", bytes.NewReader(body))
		q.Header.Set("X-LinkNest-Request", "1")
		if secure {
			q.TLS = &tls.ConnectionState{}
		}
		q.AddCookie(&http.Cookie{Name: "linknest_session", Value: "stale-old-secure-cookie"})
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, q)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		ck := w.Result().Cookies()[0]
		if ck.Secure != secure || !ck.HttpOnly || ck.Path != "/" || ck.SameSite != http.SameSiteStrictMode {
			t.Fatal("cookie flags")
		}
		return ck
	}
	https := login(true)
	plain := login(false)
	if https.Name == plain.Name || https.Name == "linknest_session" || plain.Name == "linknest_session" {
		t.Fatal("cookie collision")
	}
	for _, secure := range []bool{false, true} {
		ck := plain
		if secure {
			ck = https
		}
		q := httptest.NewRequest("GET", "http://localhost/api/state", nil)
		if secure {
			q.TLS = &tls.ConnectionState{}
		}
		q.AddCookie(&http.Cookie{Name: "linknest_session", Value: "stale"})
		q.AddCookie(ck)
		if !a.authenticated(q) {
			t.Fatal("old cookie shadows valid login")
		}
		w := httptest.NewRecorder()
		clearAdminCookie(w, q)
		expired := w.Result().Cookies()[0]
		if expired.Name != ck.Name || expired.MaxAge != -1 || expired.Secure != secure {
			t.Fatal("logout wrong cookie")
		}
	}
	q := httptest.NewRequest("GET", "http://localhost/api/state", nil)
	q.AddCookie(&http.Cookie{Name: plain.Name, Value: https.Value})
	if a.authenticated(q) {
		t.Fatal("secure token accepted via HTTP")
	}
}

func TestIconSourceValidationAndPrivacy(t *testing.T) {
	s := testStore(t)
	c := s.snapshot()
	c.Bookmarks = []Bookmark{{ID: "icon", Name: "App", URL: "https://example.com", Icon: iconPrefix + strings.Repeat("a", 64) + ".png", IconSourceURL: "https://example.com/private-source.svg"}}
	if err := validate(c, "127.0.0.1:17880"); err != nil {
		t.Fatal(err)
	}
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	if s.snapshot().Bookmarks[0].IconSourceURL != c.Bookmarks[0].IconSourceURL {
		t.Fatal("source lost")
	}
	data, _ := json.Marshal(panelGroups(c, "192.0.2.1:1234"))
	if bytes.Contains(data, []byte("private-source")) {
		t.Fatal("source leaked")
	}
	for _, source := range []string{"http://example.com/icon.svg", "https://user:pass@example.com/icon.svg", "javascript:alert(1)"} {
		c.Bookmarks[0].IconSourceURL = source
		if validate(c, "127.0.0.1:17880") == nil {
			t.Fatal("unsafe source accepted")
		}
	}
}

func TestProxySourceCompatibility(t *testing.T) {
	a := testApp(t)
	signIn(t, a)
	upstream := httptest.NewServer(a.handler())
	defer upstream.Close()
	e := newEngine(testStore(t), quiet, newFirewall(false))
	defer e.close()
	addr := freePort(t)
	r := sharedRule("admin", "admin.example", addr, upstream.URL)
	cfg := e.store.snapshot()
	cfg.Rules = []Rule{r}
	e.apply(cfg)
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	login := func(origin string) *http.Response {
		t.Helper()
		q, _ := http.NewRequest("POST", "http://"+addr+"/api/login", strings.NewReader(`{"username":"admin","password":"test-password-12345"}`))
		q.Host = "admin.example"
		q.Header.Set("Origin", origin)
		q.Header.Set("X-LinkNest-Request", "1")
		res, err := client.Do(q)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	if res := login("http://admin.example"); res.StatusCode != 403 {
		t.Fatal("original failure not reproduced", res.StatusCode)
	}
	cfg.Rules[0].Routes[0].PreserveHost = true
	e.apply(cfg)
	if res := login("http://admin.example"); res.StatusCode != 200 {
		t.Fatal("preserve Host did not fix login", res.StatusCode)
	}
	if res := login("http://evil.example"); res.StatusCode != 403 {
		t.Fatal("cross-site bypass")
	}
	cfg.Rules[0].Routes[0].PreserveHost = false
	cfg.Rules[0].Routes[0].RewriteOrigin = true
	e.apply(cfg)
	if res := login("http://admin.example"); res.StatusCode != 200 {
		t.Fatal("origin adaptation failed", res.StatusCode)
	}
	for _, bad := range []string{"http://evil.example", "null", "http://admin.example.evil", "https://admin.example", "http://admin.example/path", "http://admin.example:9999"} {
		if res := login(bad); res.StatusCode != 403 {
			t.Fatal("foreign origin rewritten", bad, res.StatusCode)
		}
	}
	req := httptest.NewRequest("GET", "https://admin.example/api", nil)
	req.Header.Set("Origin", "https://admin.example:443")
	req.Header.Set("Referer", "https://admin.example/page?q=1")
	if !proxySourceAllowed(req) {
		t.Fatal("default port should match")
	}
	req.Header.Add("Origin", "https://evil.example")
	if proxySourceAllowed(req) {
		t.Fatal("multiple origins")
	}
	req.Header.Set("Origin", "https://admin.example")
	req.Header.Set("Referer", "https://evil.example")
	if proxySourceAllowed(req) {
		t.Fatal("foreign referer")
	}
	req.Header.Del("Referer")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if proxySourceAllowed(req) {
		t.Fatal("fetch metadata bypass")
	}
}
