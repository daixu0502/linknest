package app

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func TestHTTPSProxy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("tls-ok")) }))
	defer up.Close()
	s := testStore(t)
	cert, key := testPair(t)
	cm := newCerts(s, quiet)
	defer cm.close()
	if err := cm.importPair("tls", cert, key); err != nil {
		t.Fatal(err)
	}
	e := newEngine(s, quiet, newFirewall(false))
	defer e.close()
	addr := freePort(t)
	stop, err := e.start(Rule{Kind: "web", Listen: addr, Target: up.URL, TLS: true, Certificate: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "test.example"}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	res, err := client.Get("https://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if string(b) != "tls-ok" {
		t.Fatal(string(b))
	}
}
func TestReverseProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "evil" {
			t.Error("trusted spoofed header")
		}
		w.Write([]byte("upstream:" + r.URL.Path))
	}))
	defer upstream.Close()
	s := testStore(t)
	e := newEngine(s, quiet, newFirewall(false))
	defer e.close()
	addr := freePort(t)
	r := Rule{ID: "proxy", Name: "proxy", Enabled: true, Kind: "web", Listen: addr, Target: upstream.URL, Domain: "test.example"}
	c := s.snapshot()
	c.Rules = []Rule{r}
	e.apply(c)
	client := &http.Client{Timeout: 3 * time.Second}
	get := func(host string) int {
		req, _ := http.NewRequest("GET", "http://"+addr+"/path", nil)
		req.Host = host
		req.Header.Set("X-Forwarded-For", "evil")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode == 200 && string(b) != "upstream:/path" {
			t.Fatal(string(b))
		}
		return res.StatusCode
	}
	if get("test.example") != 200 || get("wrong.example") != 421 {
		t.Fatal("host routing")
	}
	c.Blacklist = []string{"127.0.0.1"}
	s.save(c)
	if get("test.example") != 403 {
		t.Fatal("blacklist ignored")
	}
	c.Whitelist = []string{"127.0.0.1/32"}
	s.save(c)
	if get("test.example") != 200 {
		t.Fatal("whitelist ignored")
	}
	e.apply(Config{})
	if len(e.statuses()) != 0 {
		t.Fatal("listener not removed")
	}
}
func TestTCPAndUDP(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		up, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		go func() {
			for {
				c, e := up.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); io.Copy(c, c) }()
			}
		}()
		s := testStore(t)
		e := newEngine(s, quiet, newFirewall(false))
		defer e.close()
		addr := freePort(t)
		stop, err := e.start(Rule{Kind: "tcp", Listen: addr, Target: up.Addr().String()})
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte("ping"))
		b := make([]byte, 4)
		if _, err = io.ReadFull(conn, b); err != nil || string(b) != "ping" {
			t.Fatal("tcp", string(b), err)
		}
	})
	t.Run("udp", func(t *testing.T) {
		up, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		go func() {
			b := make([]byte, 1024)
			for {
				n, a, e := up.ReadFrom(b)
				if e != nil {
					return
				}
				up.WriteTo(b[:n], a)
			}
		}()
		s := testStore(t)
		e := newEngine(s, quiet, newFirewall(false))
		defer e.close()
		addr := freePort(t)
		stop, err := e.start(Rule{Kind: "udp", Listen: addr, Target: up.LocalAddr().String()})
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		conn, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte("hello"))
		b := make([]byte, 10)
		n, err := conn.Read(b)
		if err != nil || string(b[:n]) != "hello" {
			t.Fatal("udp", err)
		}
	})
}
func TestBusyPortReported(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s := testStore(t)
	e := newEngine(s, quiet, newFirewall(false))
	defer e.close()
	e.apply(Config{Rules: []Rule{{ID: "busy", Name: "busy", Kind: "tcp", Enabled: true, Listen: l.Addr().String(), Target: "127.0.0.1:9"}}})
	st := e.statuses()
	if len(st) != 1 || st[0].State != "error" {
		t.Fatal(st)
	}
}
