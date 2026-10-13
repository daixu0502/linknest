package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

func TestRecordSourcesMigrateAndRemainIndependent(t *testing.T) {
	c := Config{Schema: 2, DDNS: []DDNSRule{{ID: "task", Name: "task", IPv4: IPSource{Mode: "interface", Interface: "wan"}, IPv6: IPSource{Mode: "interface", Interface: "wan6"}, Records: []DDNSRecord{{ID: "one", Type: "A", Value: "{ipv4Addr}", Enabled: true}, {ID: "two", Type: "A", Value: "{ipv4Addr}", Enabled: true, Source: IPSource{Mode: "interface", Interface: "wan2"}}, {ID: "six", Type: "AAAA", Value: "{ipv6Addr}", Enabled: true}}}}}
	migrateConfig(&c)
	migrateConfig(&c)
	r := c.DDNS[0].Records
	if r[0].Source.Interface != "wan" || r[1].Source.Interface != "wan2" || r[2].Source.Interface != "wan6" {
		t.Fatal(r)
	}
	d := newDNS(testStore(t), quiet)
	defer d.close()
	calls := map[string]int{}
	d.detect = func(ctx context.Context, s IPSource, v6 bool) (string, error) {
		calls[s.Interface]++
		if s.Interface == "wan" {
			return "8.8.8.8", nil
		}
		if s.Interface == "wan2" {
			return "1.1.1.1", nil
		}
		return "", errors.New("no IPv6 on wan6")
	}
	v := d.detectRecords(context.Background(), c.DDNS[0], "")
	if v[0].Value != "8.8.8.8" || v[1].Value != "1.1.1.1" || v[2].Error == "" || calls["wan2"] != 1 {
		t.Fatal(v, calls)
	}
}
func TestCertificateTasksAndProgressPersistSafely(t *testing.T) {
	s := testStore(t)
	m := newCerts(s, quiet)
	r := CertRequest{ID: "cert", Name: "Saved task", Domains: []string{"example.com"}, Zone: "example.com", Email: "test@example.com", Account: DNSAccount{AccessKeyID: "fake-id", Secret: "task-only-secret"}}
	if e := m.saveTask(r); e != nil {
		t.Fatal(e)
	}
	meta, _ := os.ReadFile(filepath.Join(s.dir, "certificates", "cert.renew.json"))
	if strings.Contains(string(meta), "task-only-secret") {
		t.Fatal("plaintext secret")
	}
	r.Account.Secret = ""
	r.Name = "Edited task"
	if e := m.saveTask(r); e != nil {
		t.Fatal(e)
	}
	saved, _ := m.task("cert")
	secret, e := s.unseal(saved.Account.Secret)
	if e != nil || secret != "task-only-secret" {
		t.Fatal("secret not retained")
	}
	b, _ := json.Marshal(m.tasks())
	if strings.Contains(string(b), "enc:") || !strings.Contains(string(b), `"secretSet":true`) {
		t.Fatal("task redaction")
	}
	m.progress("cert", "dns_wait", "waiting on authoritative servers")
	m.finish("cert", errors.New("DNS timeout"))
	m.close()
	m = newCerts(s, quiet)
	defer m.close()
	if len(m.status()) != 1 || m.status()[0].State != "error" || len(m.status()[0].Steps) != 2 {
		t.Fatal(m.status())
	}
	c := s.snapshot()
	c.Rules = []Rule{{Certificate: "cert"}}
	s.save(c)
	if m.remove("cert") == nil {
		t.Fatal("in-use certificate removed")
	}
	c.Rules = nil
	c.AdminTLS = AdminTLSConfig{Certificate: "cert"}
	s.save(c)
	if m.remove("cert") == nil {
		t.Fatal("admin certificate removed")
	}
	c.AdminTLS = AdminTLSConfig{}
	s.save(c)
	if e := m.remove("cert"); e != nil {
		t.Fatal(e)
	}
	if len(m.tasks()) != 0 || len(m.status()) != 0 {
		t.Fatal("task not removed")
	}
}
func TestAuthoritativeDNSBypassesStaleRecursiveCache(t *testing.T) {
	targets := []txtTarget{{Label: "ns1", Authority: true}, {Label: "ns2", Authority: true}, {Label: "recursive"}}
	query := func(ctx context.Context, t txtTarget, n, v string) (bool, string) { return t.Authority, "safe summary" }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := waitExpectedTXT(ctx, targets, "_acme-challenge.example.com", "not-logged", query, func(s string) {
		if strings.Contains(s, "not-logged") {
			t.Fatal("token leaked")
		}
	}, time.Millisecond); e != nil {
		t.Fatal(e)
	}
	ctx2, stop := context.WithCancel(context.Background())
	stop()
	if e := waitExpectedTXT(ctx2, targets, "n", "v", func(context.Context, txtTarget, string, string) (bool, string) { return false, "not found" }, func(string) {}, time.Millisecond); e == nil {
		t.Fatal("missing TXT accepted")
	}
}
func TestAdminHTTPSAndHTTPSharePort(t *testing.T) {
	a := testApp(t)
	cert, key := testPair(t)
	if e := a.certs.importPair("admin", cert, key); e != nil {
		t.Fatal(e)
	}
	c := a.store.snapshot()
	c.AdminTLS = AdminTLSConfig{Enabled: true, Certificate: "admin"}
	if e := a.store.save(c); e != nil {
		t.Fatal(e)
	}
	a.admin = "127.0.0.1:0"
	ln, e := a.adminListener()
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: a.handler(), ReadHeaderTimeout: time.Second}
	go srv.Serve(ln)
	defer srv.Close()
	addr := ln.Addr().String()
	idle, _ := net.Dial("tcp", addr)
	defer idle.Close()
	plain := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := plain.Get("http://" + addr + "/")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "test.example"}}
	defer tr.CloseIdleConnections()
	secure := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	res, e = secure.Get("https://" + addr + "/")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.TLS == nil || res.StatusCode != 200 {
		t.Fatal("TLS failed")
	}
	c.AdminTLS.Redirect = true
	a.store.save(c)
	res, e = plain.Get("http://" + addr + "/?q=1")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 307 || res.Header.Get("Location") != "https://"+addr+"/?q=1" {
		t.Fatal("redirect changed port", res.Header)
	}
	os.Remove(filepath.Join(a.store.dir, "certificates", "admin.pem"))
	res, e = plain.Get("http://" + addr + "/")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("lost certificate locked out HTTP")
	}
}
func TestDualProtocolForwardAndRollback(t *testing.T) {
	tcp, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	udp, e := net.ListenPacket("udp", tcp.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	go func() {
		b := make([]byte, 128)
		for {
			n, addr, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], addr)
		}
	}()
	s := testStore(t)
	eng := newEngine(s, quiet, newFirewall(false))
	defer eng.close()
	r := Rule{ID: "dual", Name: "Dual", Enabled: true, Kind: "tcpudp", Listen: freePort(t), Target: tcp.Addr().String(), OpenFirewall: true}
	stop, e := eng.start(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, proto := range []string{"tcp", "udp"} {
		conn, e := net.DialTimeout(proto, r.Listen, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		conn.Write([]byte("ping"))
		b := make([]byte, 4)
		_, e = io.ReadFull(conn, b)
		conn.Close()
		if e != nil || string(b) != "ping" {
			t.Fatal(proto, e)
		}
	}
	stop()
	fw := buildFirewall([]Rule{r}, Config{}, false)
	if !strings.Contains(fw, "-p tcp") || !strings.Contains(fw, "-p udp") {
		t.Fatal(fw)
	}
	occupied, e := net.ListenPacket("udp", r.Listen)
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	if _, e = eng.start(r); e == nil {
		t.Fatal("partial dual start accepted")
	}
	check, e := net.Listen("tcp", r.Listen)
	if e != nil {
		t.Fatal("TCP not rolled back", e)
	}
	check.Close()
	c := s.snapshot()
	c.Rules = []Rule{r, {ID: "udp", Name: "Conflict", Enabled: true, Kind: "udp", Listen: r.Listen, Target: r.Target}}
	if validate(c, "127.0.0.1:17880") == nil {
		t.Fatal("dual conflict allowed")
	}
}
func TestAdminTLSRequiresCertificateAndMatchingRedirectHost(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	c := a.store.snapshot()
	c.AdminTLS = AdminTLSConfig{Enabled: true, Redirect: true, Certificate: "missing"}
	if w := request(a, "PUT", "/api/config", c, ck); w.Code != 400 {
		t.Fatal(w.Code)
	}
	cert, key := testPair(t)
	a.certs.importPair("admin", cert, key)
	c.AdminTLS.Certificate = "admin"
	if w := request(a, "PUT", "/api/config", c, ck); w.Code != 400 {
		t.Fatal("uncovered hostname accepted", w.Code)
	}
	b, _ := json.Marshal(c)
	req := httptest.NewRequest("PUT", "http://test.example/api/config", strings.NewReader(string(b)))
	req.Header.Set("X-LinkNest-Request", "1")
	req.AddCookie(ck)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	// Replacing a certificate while redirect stays on must recheck the host.
	a.certs.importPair("replacement", cert, key)
	c.AdminTLS.Certificate = "replacement"
	b, _ = json.Marshal(c)
	req = httptest.NewRequest("PUT", "https://uncovered.example/api/config", strings.NewReader(string(b)))
	req.Header.Set("X-LinkNest-Request", "1")
	// Model an authenticated HTTPS session; HTTP tokens are no longer shared.
	ck.Name = adminCookieName(req)
	sess := a.sessions[ck.Value]
	sess.secure = true
	a.sessions[ck.Value] = sess
	req.AddCookie(ck)
	w = httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatal("certificate replacement bypassed hostname validation", w.Code)
	}
}
