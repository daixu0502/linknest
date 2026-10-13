package app

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestV1MigrationPreservesEnabled(t *testing.T) {
	c := Config{Schema: 1, Rules: []Rule{{ID: "old", Name: "old", Kind: "web", Enabled: true, Listen: "127.0.0.1:18801", Domain: "home.example.com", Target: "http://192.0.2.1:80"}}, DDNS: []DDNSRule{{ID: "dns", Name: "dns", Enabled: true, Zone: "example.com", RR: "home", Type: "A", SourceURL: "https://api4.ipify.org"}}}
	migrateConfig(&c)
	migrateConfig(&c)
	if c.Schema != configSchema || !c.Rules[0].Enabled || len(c.Rules[0].Routes) != 1 || len(c.DDNS[0].Records) != 1 || !c.DDNS[0].Enabled || c.DDNS[0].Records[0].Source.Mode != "url" {
		t.Fatal(c)
	}
	if err := validate(c, "127.0.0.1:17880"); err != nil {
		t.Fatal(err)
	}
}
func TestTaskCredentialsEncryptedRedactedAndReferenced(t *testing.T) {
	s := testStore(t)
	c := s.snapshot()
	c.DDNS = []DDNSRule{{ID: "a", Name: "a", Account: DNSAccount{AccessKeyID: "fake-a", Secret: "unique-private-key"}}, {ID: "b", Name: "b", CredentialRef: "a"}}
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.dir, "config.json"))
	if strings.Contains(string(b), "unique-private-key") {
		t.Fatal("plaintext on disk")
	}
	clean, flags := redactedConfig(s.snapshot())
	b, _ = json.Marshal(clean)
	if strings.Contains(string(b), "enc:") || !flags["b"] {
		t.Fatal("secret leakage / reference failure")
	}
	if err := s.save(clean); err != nil {
		t.Fatal(err)
	}
	a, err := s.dnsAccount("b")
	if err != nil || a.Secret != "unique-private-key" {
		t.Fatal(a.AccessKeyID, err)
	}
	clean.DDNS[0].CredentialRef = "b"
	if validate(clean, "127.0.0.1:17880") == nil {
		t.Fatal("cycle accepted")
	}
	clean.DDNS[0].CredentialRef = ""
	clean.DDNS = clean.DDNS[1:]
	if validate(clean, "127.0.0.1:17880") == nil {
		t.Fatal("dangling reference accepted")
	}
}
func TestSharedListenerRoutesHotUpdate(t *testing.T) {
	one := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) }))
	defer one.Close()
	two := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) }))
	defer two.Close()
	s := testStore(t)
	e := newEngine(s, quiet, newFirewall(false))
	defer e.close()
	addr := freePort(t)
	c := s.snapshot()
	c.Rules = []Rule{{ID: "main", Name: "main", Kind: "web", Enabled: true, Listen: addr, Routes: []WebRoute{{ID: "first", Name: "first", Enabled: true, Domains: []string{"a.example.com"}, Target: one.URL}, {ID: "second", Name: "second", Enabled: true, Domains: []string{"*.example.com"}, Target: two.URL}}}}
	e.apply(c)
	original := e.rules["main"]
	get := func(host string) (int, string) {
		req, _ := http.NewRequest("GET", "http://"+addr, nil)
		req.Host = host
		res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, b := get("a.example.com"); code != 200 || b != "one" {
		t.Fatal(code, b)
	}
	if code, b := get("b.example.com"); code != 200 || b != "two" {
		t.Fatal(code, b)
	}
	if code, _ := get("example.com"); code != 421 {
		t.Fatal(code)
	}
	c.Rules[0].Routes[0].Enabled = false
	e.apply(c)
	if original != e.rules["main"] {
		t.Fatal("child edit restarted listener")
	}
	if _, b := get("a.example.com"); b != "two" {
		t.Fatal(b)
	}
}
func TestIPv6OnlyListener(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available")
	}
	addr := l.Addr().String()
	l.Close()
	s := testStore(t)
	e := newEngine(s, quiet, newFirewall(false))
	defer e.close()
	stop, err := e.start(Rule{ID: "v6", Kind: "web", Network: "ipv6", Listen: addr})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	c, err := net.DialTimeout("tcp6", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if strings.Contains(buildFirewall([]Rule{{Kind: "web", Network: "ipv6", Listen: "[::]:18081", OpenFirewall: true}}, Config{}, false), "18081") {
		t.Fatal("IPv6 rule widened to IPv4")
	}
}
func TestDDNSIndependentRecordResults(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.Form.Get("Action") {
		case "DescribeDomainRecords":
			w.Write([]byte(`{"TotalCount":0,"DomainRecords":{"Record":[]}}`))
		case "AddDomainRecord":
			if r.Form.Get("TTL") != "600" || r.Form.Get("Line") != "default" {
				t.Error("TTL/line missing")
			}
			w.Write([]byte(`{"RecordId":"created"}`))
		default:
			t.Error("unexpected API")
		}
	}))
	defer mock.Close()
	s := testStore(t)
	c := s.snapshot()
	c.DDNS = []DDNSRule{{ID: "task", Name: "task", Account: DNSAccount{AccessKeyID: "fake", Secret: "fake"}, Records: []DDNSRecord{{ID: "v4", Enabled: true, Zone: "example.com", Domain: "home.example.com", Type: "A", Value: "{ipv4Addr}", TTL: 600, Line: "default"}, {ID: "v6", Enabled: true, Zone: "example.com", Domain: "home.example.com", Type: "AAAA", Value: "{ipv6Addr}", TTL: 600, Line: "default"}, {ID: "alias", Enabled: true, Zone: "example.com", Domain: "www.example.com", Type: "CNAME", Value: "home.example.com", TTL: 600, Line: "default"}}}}
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	d := newDNS(s, quiet)
	defer d.close()
	d.client = func(a DNSAccount) AliDNS { return AliDNS{ID: a.AccessKeyID, Secret: a.Secret, Endpoint: mock.URL} }
	d.detect = func(ctx context.Context, src IPSource, v6 bool) (string, error) {
		if v6 {
			return "", errors.New("no IPv6")
		}
		return "8.8.4.4", nil
	}
	st := d.updateTask(context.Background(), s.snapshot().DDNS[0])
	if st.State != "error" || len(st.Records) != 3 || st.Records[0].State != "success" || st.Records[1].State != "error" || st.Records[2].State != "success" {
		t.Fatal(st)
	}
}
func TestPublicIPSelection(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "100.64.1.1", "192.0.2.1", "fe80::1", "fd00::1", "2001:db8::1", "240.0.0.1"} {
		if publicIP(net.ParseIP(s)) {
			t.Fatal(s)
		}
	}
	if !publicIP(net.ParseIP("8.8.8.8")) || !publicIP(net.ParseIP("2606:4700:4700::1111")) {
		t.Fatal("valid address rejected")
	}
	_, e := pickInterface([]InterfaceAddress{{Name: "wan", IPv6: []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}}}, "", true)
	if e == nil {
		t.Fatal("ambiguous interface selection")
	}
}
func TestCertificateMultiSANAndIndependentCredentials(t *testing.T) {
	r := CertRequest{ID: "multi", Domains: []string{"example.com", "*.example.com", "home.example.com"}, Zone: "example.com", Email: "test@example.com"}
	if e := validateCertRequest(r); e != nil {
		t.Fatal(e)
	}
	fqdn, rr, e := challengeName(r, "example.com")
	if e != nil || fqdn != "_acme-challenge.example.com" || rr != "_acme-challenge" {
		t.Fatal(fqdn, rr, e)
	}
	_, rr, e = challengeName(r, "home.example.com")
	if e != nil || rr != "_acme-challenge.home" {
		t.Fatal(rr, e)
	}
	if _, _, e = challengeName(r, "evil.example.net"); e == nil {
		t.Fatal("unexpected auth domain accepted")
	}
	s := testStore(t)
	c := s.snapshot()
	c.DNS = DNSAccount{AccessKeyID: "shared", Secret: "shared-secret"}
	s.save(c)
	m := newCerts(s, quiet)
	defer m.close()
	if m.start(r) == nil {
		t.Fatal("certificate silently reused DDNS credentials")
	}
}
func TestPortalIsolationAndPasswordRetention(t *testing.T) {
	s := testStore(t)
	c := s.snapshot()
	c.Bookmarks = []Bookmark{{ID: "link", Name: "Private Bookmarks", URL: "https://example.com"}}
	c.Rules = []Rule{{ID: "listener", Name: "Listener", Kind: "web", Listen: "127.0.0.1:18000", Routes: []WebRoute{{ID: "portal", Name: "Links", Backend: "bookmarks", AccessPassword: "test-private-password", Enabled: true}}}}
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	clean, _ := redactedConfig(s.snapshot())
	if clean.Rules[0].Routes[0].AccessPassword != "" {
		t.Fatal("hash leaked")
	}
	if err := s.save(clean); err != nil {
		t.Fatal(err)
	}
	route := s.snapshot().Rules[0].Routes[0]
	if bcrypt.CompareHashAndPassword([]byte(route.AccessPassword), []byte("test-private-password")) != nil {
		t.Fatal("password not preserved")
	}
	p := newPortal(s, quiet)
	serve := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, "http://portal.example"+path, strings.NewReader(body))
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		q.Header.Set("Origin", "http://portal.example")
		if cookie != nil {
			q.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		p.serve(route, w, q)
		return w
	}
	if w := serve("GET", "/", "", nil); strings.Contains(w.Body.String(), "Private Bookmarks") {
		t.Fatal("unauthenticated bookmarks leak")
	}
	if w := serve("GET", "/api/state", "", nil); w.Code != 404 {
		t.Fatal("admin API exposed", w.Code)
	}
	w := serve("POST", "/__linknest/login", url.Values{"password": {"test-private-password"}}.Encode(), nil)
	if w.Code != 303 || len(w.Result().Cookies()) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if w := serve("GET", "/", "", cookie); !strings.Contains(w.Body.String(), "Private Bookmarks") {
		t.Fatal("login failed")
	}
	if w := serve("POST", "/__linknest/wake", "id=test", cookie); w.Code != 403 {
		t.Fatal("CSRF missing")
	}
	if w := serve("POST", "/__linknest/wake", "id=test&csrf="+cookie.Value, cookie); w.Code != 404 {
		t.Fatal("bookmark backend allowed WOL")
	}
}

func TestDisabledPortalImportRequiresPasswordBeforeEnabling(t *testing.T) {
	s := testStore(t)
	c := s.snapshot()
	c.Rules = []Rule{{ID: "main", Name: "Main", Kind: "web", Listen: "127.0.0.1:18000", Routes: []WebRoute{{ID: "portal", Name: "Portal", Backend: "wol", Enabled: true}}}}
	if err := s.save(c); err != nil {
		t.Fatal("disabled import should allow credentials to be filled later:", err)
	}
	c.Rules[0].Enabled = true
	if err := s.save(c); err == nil {
		t.Fatal("enabled portal accepted without a password")
	}
	c.Rules[0].Routes[0].AccessPassword = "local-test-password"
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
}

func TestFutureSchemaIsNotDowngraded(t *testing.T) {
	s := testStore(t)
	c := s.snapshot()
	c.Schema = configSchema + 1
	migrateConfig(&c)
	if c.Schema != configSchema+1 || validate(c, "127.0.0.1:17880") == nil || s.save(c) == nil {
		t.Fatal("future schema was accepted or silently downgraded")
	}
}
