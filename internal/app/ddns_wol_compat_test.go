package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAllDNSRecordValues(t *testing.T) {
	cases := map[string]string{"A": "8.8.8.8", "AAAA": "2606:4700:4700::1111", "CNAME": "target.example.com.", "MX": "mail.example.com.", "TXT": "v=spf1 -all", "SRV": "0 5 443 target.example.com.", "NS": "ns.example.com.", "CAA": `0 issue "letsencrypt.org"`, "PTR": "ptr.example.com.", "SVCB": `1 . alpn="h2,h3"`, "HTTPS": "0 target.example.com.", "REDIRECT_URL": "https://example.com/path?q=1", "FORWARD_URL": "https://example.com/"}
	for typ, value := range cases {
		t.Run(typ, func(t *testing.T) {
			r := DDNSRecord{ID: "rec", Domain: "_test._tcp.example.com", Type: typ, Value: value, Priority: 10, TTL: 600, Line: "default"}
			if _, e := recordValue(r, "", ""); e != nil {
				t.Fatal(e)
			}
			d := DDNSRule{ID: "task", Name: "Task", Interval: 300, Records: []DDNSRecord{r}}
			if e := validateDDNSTask(d, Config{DDNS: []DDNSRule{d}}, func(string) error { return nil }); e != nil {
				t.Fatal(e)
			}
		})
	}
	for _, r := range []DDNSRecord{{Type: "MX", Value: "mail.example.com", Priority: 0}, {Type: "SRV", Value: "0 1 70000 example.com"}, {Type: "CAA", Value: `256 issue "example.com"`}, {Type: "HTTPS", Value: "0 ."}, {Type: "TXT", Value: "{ipv4Addr}"}, {Type: "SOA", Value: "invalid"}, {Type: "FORWARD_URL", Value: "javascript:alert(1)"}} {
		if _, e := recordValue(r, "8.8.8.8", ""); e == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}
func TestDNSZonePaginationAndMXPriority(t *testing.T) {
	var adds atomic.Int32
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.Form.Get("Action") {
		case "DescribeDomains":
			if r.Form.Get("PageNumber") == "1" {
				fmt.Fprint(w, `{"TotalCount":101,"Domains":{"Domain":[{"DomainName":"example.co.uk"}]}}`)
			} else {
				fmt.Fprint(w, `{"TotalCount":101,"Domains":{"Domain":[{"DomainName":"sub.example.co.uk"}]}}`)
			}
		case "DescribeDomainRecords":
			fmt.Fprint(w, `{"DomainRecords":{"Record":[{"RecordId":"old","RR":"@","Type":"MX","Value":"mail.example.com","Priority":5,"TTL":600}]}}`)
		case "UpdateDomainRecord":
			if r.Form.Get("Priority") != "10" {
				t.Error("MX priority missing")
			}
			adds.Add(1)
			fmt.Fprint(w, `{"RecordId":"old"}`)
		default:
			t.Error("unexpected API")
		}
	}))
	defer mock.Close()
	a := AliDNS{ID: "mock", Secret: "mock", Endpoint: mock.URL}
	z, e := a.zones(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for domain, want := range map[string]string{"home.sub.example.co.uk": "sub.example.co.uk", "example.co.uk": "example.co.uk"} {
		got, e := matchDNSZone(domain, z)
		if e != nil || got != want {
			t.Fatal(got, e)
		}
	}
	if _, e = matchDNSZone("evil-example.co.uk", z); e == nil {
		t.Fatal("unsafe zone suffix")
	}
	changed, e := a.upsertRecord(context.Background(), "example.com", "@", "MX", "mail.example.com", 600, "default", 10)
	if e != nil || !changed || adds.Load() != 1 {
		t.Fatal(changed, e)
	}
}
func TestDNSAutosyncSaveAndQueuedRerun(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var detections atomic.Int32
	var writes atomic.Int32
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("Action") == "DescribeDomainRecords" {
			fmt.Fprint(w, `{"TotalCount":0}`)
		} else {
			writes.Add(1)
			fmt.Fprint(w, `{"RecordId":"new"}`)
		}
	}))
	defer mock.Close()
	a.dns.client = func(v DNSAccount) AliDNS { return AliDNS{ID: v.AccessKeyID, Secret: v.Secret, Endpoint: mock.URL} }
	a.dns.detect = func(ctx context.Context, s IPSource, v6 bool) (string, error) {
		n := detections.Add(1)
		started <- struct{}{}
		if n == 1 {
			<-release
		}
		return "8.8.8.8", ctx.Err()
	}
	c := a.store.snapshot()
	c.DDNS = []DDNSRule{{ID: "task", Name: "Auto", Interval: 300, Enabled: true, Account: DNSAccount{AccessKeyID: "mock", Secret: "mock"}, Records: []DDNSRecord{{ID: "one", Zone: "example.com", Domain: "one.example.com", Type: "A", Value: "{ipv4Addr}", Enabled: true, TTL: 600, Line: "default", Source: IPSource{Mode: "auto"}}}}}
	if w := request(a, "PUT", "/api/config", c, ck); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("save did not start immediately")
	}
	c, _ = redactedConfig(a.store.snapshot())
	rec := c.DDNS[0].Records[0]
	rec.ID = "two"
	rec.Domain = "two.example.com"
	c.DDNS[0].Records = append(c.DDNS[0].Records, rec)
	if w := request(a, "PUT", "/api/config", c, ck); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	close(release)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("pending config lost")
	}
	waitDNSIdle(t, a.dns)
	if detections.Load() != 2 || writes.Load() != 2 {
		t.Fatal("wrong pass/write count", detections.Load(), writes.Load())
	}
	c, _ = redactedConfig(a.store.snapshot())
	c.Bookmarks = []Bookmark{{ID: "link", Name: "unrelated", URL: "https://example.com"}}
	request(a, "PUT", "/api/config", c, ck)
	waitDNSIdle(t, a.dns)
	if detections.Load() != 2 {
		t.Fatal("unrelated save retriggered DNS")
	}
	c.DDNS[0].Enabled = false
	request(a, "PUT", "/api/config", c, ck)
	c.DDNS[0].Records[0].Value = "1.1.1.1"
	request(a, "PUT", "/api/config", c, ck)
	waitDNSIdle(t, a.dns)
	if writes.Load() != 2 {
		t.Fatal("disabled task wrote DNS")
	}
}
func waitDNSIdle(t *testing.T, d *DNSManager) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		n := len(d.running)
		d.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("DNS did not finish")
}

func TestDeviceTCPOnlineAndUnknown(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	d := Device{ID: "test", IP: "127.0.0.1", CheckPort: ln.Addr().(*net.TCPAddr).Port}
	if s := checkDevice(context.Background(), d); s.State != "online" {
		t.Fatal(s)
	}
	ln.Close()
	if s := checkDevice(context.Background(), d); s.State != "unknown" {
		t.Fatal(s)
	}
	if s := checkDevice(context.Background(), Device{}); s.State != "unconfigured" {
		t.Fatal(s)
	}
	packet := []byte{8, 0, 0, 0, 1, 2, 3, 4, 5}
	sum := icmpChecksum(packet)
	packet[2] = byte(sum >> 8)
	packet[3] = byte(sum)
	if icmpChecksum(packet) != 0 {
		t.Fatal("bad ICMP checksum")
	}
}

func TestICMPLoopback(t *testing.T) {
	if os.Getenv("LINKNEST_TEST_ICMP") != "1" {
		t.Skip("requires explicit NET_RAW test container")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pingDevice(ctx, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func TestSSHProbeAndExplicitTrust(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	var authCalls atomic.Int32
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		authCalls.Add(1)
		return nil, fmt.Errorf("no auth expected")
	}}
	cfg.AddHostKey(signer)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			raw, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer raw.Close(); raw.SetDeadline(time.Now().Add(time.Second)); ssh.NewServerConn(raw, cfg) }()
		}
	}()
	fp, e := probeSSH(context.Background(), ln.Addr().String())
	if e != nil || fp != ssh.FingerprintSHA256(signer.PublicKey()) || authCalls.Load() != 0 {
		t.Fatal(fp, e)
	}
	a := testApp(t)
	ck := signIn(t, a)
	c := a.store.snapshot()
	c.SSHHosts = []SSHHost{{ID: "ssh", Name: "Test", Username: "tester", Address: ln.Addr().String()}}
	if w := request(a, "PUT", "/api/config", c, ck); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	q := map[string]string{"id": "ssh", "address": ln.Addr().String(), "previous": "", "fingerprint": fp, "adminPassword": "test-password-12345"}
	if w := request(a, "POST", "/api/ssh/trust", q, ck); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if a.store.snapshot().SSHHosts[0].Fingerprint != fp {
		t.Fatal("pin not saved")
	}
	q["fingerprint"] = "SHA256:wrong"
	if w := request(a, "POST", "/api/ssh/trust", q, ck); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if a.store.snapshot().SSHHosts[0].Fingerprint != fp {
		t.Fatal("unverified pin replaced")
	}
	q["fingerprint"] = fp
	if w := request(a, "POST", "/api/ssh/trust", q, ck); w.Code != 409 {
		t.Fatal("stale config accepted")
	}
	c = a.store.snapshot()
	c.SSHHosts[0].Fingerprint = "SHA256:previous-server-key"
	a.store.save(c)
	q["previous"] = "SHA256:previous-server-key"
	if w := request(a, "POST", "/api/ssh/trust", q, ck); w.Code != 200 {
		t.Fatal("explicit replacement failed", w.Body.String())
	}
	if a.store.snapshot().SSHHosts[0].Fingerprint != fp {
		t.Fatal("confirmed replacement not persisted")
	}
}

func TestProxySamePortTLSRedirect(t *testing.T) {
	s := testStore(t)
	cert, key := testPair(t)
	cm := newCerts(s, quiet)
	defer cm.close()
	if e := cm.importPair("tls", cert, key); e != nil {
		t.Fatal(e)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend") }))
	defer upstream.Close()
	e := newEngine(s, quiet, newFirewall(false))
	defer e.close()
	addr := freePort(t)
	c := s.snapshot()
	c.Rules = []Rule{{ID: "web", Name: "Web", Kind: "web", Enabled: true, Listen: addr, TLS: true, RedirectHTTP: true, Certificate: "tls", Routes: []WebRoute{{ID: "route", Name: "Route", Enabled: true, Domains: []string{"test.example"}, Target: upstream.URL}}}}
	e.apply(c)
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(host string) *http.Response {
		r, _ := http.NewRequest("GET", "http://"+addr+"/a%2Fb?q=1", nil)
		r.Host = host
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	res := get("test.example:18443")
	if res.StatusCode != 307 || res.Header.Get("Location") != "https://test.example:18443/a%2Fb?q=1" {
		t.Fatal(res.StatusCode, res.Header)
	}
	if res = get("evil.example"); res.StatusCode != 421 {
		t.Fatal("unknown host redirected")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "test.example"}}
	defer tr.CloseIdleConnections()
	client.Transport = tr
	r, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	r.Host = "test.example"
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	c.Rules[0].RedirectHTTP = false
	e.apply(c)
	client.Transport = nil
	if res = get("test.example"); res.StatusCode != 400 {
		t.Fatal("plaintext exposed backend")
	}
}

func TestUserMACRegression(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	c := a.store.snapshot()
	c.Devices = []Device{{ID: "pc", Name: "PC", MAC: "02-AB-CD-EF-12-34", Broadcast: "192.168.1.255", IP: "192.168.1.2", CheckPort: 3389}}
	w := request(a, "PUT", "/api/config", c, ck)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	b, _ := json.Marshal(a.store.snapshot().Devices)
	if !strings.Contains(string(b), "02:AB:CD:EF:12:34") {
		t.Fatal(string(b))
	}
}
