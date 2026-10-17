package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Bind only loopback and use a private CA. No external DNS, router or real
// certificates are involved in these proxy integration tests.
func testWebProxy(t *testing.T, target string, secure, preserve, rewrite, skip bool) (*Engine, string, *tls.Config) {
	t.Helper()
	s := testStore(t)
	e := newEngine(s, quiet, newFirewall(false))
	t.Cleanup(e.close)
	addr := freePort(t)
	_, port, _ := net.SplitHostPort(addr)
	host := net.JoinHostPort("test.example", port)
	rule := sharedRule("ws-test", "test.example", addr, target)
	rule.TLS, rule.Certificate = secure, "proxy-test"
	rule.Routes[0].PreserveHost = preserve
	rule.Routes[0].RewriteOrigin = rewrite
	rule.Routes[0].SkipTLSVerify = skip
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if secure {
		cert, key := testPair(t)
		manager := newCerts(s, quiet)
		t.Cleanup(manager.close)
		if err := manager.importPair(rule.Certificate, cert, key); err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(cert)
		tlsConfig.RootCAs, tlsConfig.ServerName = roots, "test.example"
	}
	c := s.snapshot()
	c.Rules = []Rule{rule}
	if err := validate(c, "127.0.0.1:17880"); err != nil {
		t.Fatal(err)
	}
	e.apply(c)
	return e, host, tlsConfig
}

func proxyTestDial(_ context.Context, _, address string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 3*time.Second)
}

func TestProxyAutomaticForwardingHeaders(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, preserve := range []bool{false, true} {
			name := map[bool]string{false: "http", true: "https"}[secure]
			if preserve {
				name += "-preserve-host"
			}
			t.Run(name, func(t *testing.T) {
				seen := make(chan *http.Request, 1)
				backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- r.Clone(r.Context())
					io.WriteString(w, "ok")
				}))
				defer backend.Close()
				_, host, tlsConfig := testWebProxy(t, backend.URL, secure, preserve, false, false)
				transport := &http.Transport{Proxy: nil, DialContext: proxyTestDial, TLSClientConfig: tlsConfig}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				scheme := map[bool]string{false: "http", true: "https"}[secure]
				req, _ := http.NewRequest("GET", scheme+"://"+host+"/api/state", nil)
				req.Header.Set("X-Forwarded-For", "203.0.113.7")
				req.Header.Set("X-Forwarded-Host", "spoof.invalid")
				req.Header.Set("X-Forwarded-Proto", "spoof")
				req.Header.Set("Forwarded", "for=203.0.113.7;proto=spoof")
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if res.StatusCode != http.StatusOK {
					t.Fatal(res.Status)
				}
				r := <-seen
				if r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("X-Forwarded-Host") != host || r.Header.Get("X-Forwarded-Proto") != scheme || r.Header.Get("Forwarded") != "" {
					t.Fatal("incorrect or spoofed forwarding headers", r.Header)
				}
				wantHost := strings.TrimPrefix(backend.URL, "http://")
				if preserve {
					wantHost = host
				}
				if r.Host != wantHost {
					t.Fatalf("Host %q, want %q", r.Host, wantHost)
				}
			})
		}
	}
}

func TestProxyWebSocketRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name            string
		publicTLS       bool
		backendTLS      bool
		websocketTarget bool
		rewriteOrigin   bool
	}{
		{"ws-http", false, false, false, false},
		{"wss-http", true, false, false, false},
		{"ws-ws", false, false, true, false},
		{"wss-wss", true, true, true, false},
		{"wss-https", true, true, false, false},
		{"wss-ws-origin-adaptation", true, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan *http.Request, 1)
			upgrader := websocket.Upgrader{Subprotocols: []string{"motrix-test"}, CheckOrigin: func(*http.Request) bool { return true }}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Clone(r.Context())
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if conn.WriteMessage(websocket.TextMessage, []byte("server-push")) != nil {
					return
				}
				for {
					kind, data, err := conn.ReadMessage()
					if err != nil || conn.WriteMessage(kind, data) != nil {
						return
					}
				}
			})
			backend := httptest.NewUnstartedServer(handler)
			if tc.backendTLS {
				backend.StartTLS()
			} else {
				backend.Start()
			}
			defer backend.Close()
			target := backend.URL + "/base"
			if tc.websocketTarget {
				target = strings.Replace(target, "http", "ws", 1)
			}
			engine, host, tlsConfig := testWebProxy(t, target, tc.publicTLS, true, tc.rewriteOrigin, tc.backendTLS)
			publicScheme := map[bool]string{false: "http", true: "https"}[tc.publicTLS]
			wsScheme := map[bool]string{false: "ws", true: "wss"}[tc.publicTLS]
			dialer := websocket.Dialer{NetDialContext: proxyTestDial, TLSClientConfig: tlsConfig, Subprotocols: []string{"motrix-test"}, HandshakeTimeout: 3 * time.Second}
			headers := http.Header{"Origin": {publicScheme + "://" + host}, "X-Forwarded-Proto": {"spoof"}, "Cookie": {"session=test-only"}}
			ws, res, err := dialer.Dial(wsScheme+"://"+host+"/rpc/events?cursor=1", headers)
			if err != nil {
				if res != nil {
					res.Body.Close()
				}
				t.Fatal(err)
			}
			defer ws.Close()
			ws.SetReadDeadline(time.Now().Add(5 * time.Second))
			if res.StatusCode != http.StatusSwitchingProtocols || ws.Subprotocol() != "motrix-test" {
				t.Fatal("upgrade or subprotocol lost")
			}
			r := <-seen
			wantOrigin := publicScheme + "://" + host
			if tc.rewriteOrigin {
				wantOrigin = "http://" + host
			}
			if r.Host != host || r.Header.Get("Origin") != wantOrigin || r.Header.Get("X-Forwarded-Proto") != publicScheme || r.Header.Get("X-Forwarded-Host") != host || r.Header.Get("Cookie") != "session=test-only" || r.URL.Path != "/base/rpc/events" || r.URL.RawQuery != "cursor=1" {
				t.Fatalf("handshake changed: host=%s url=%s headers=%v", r.Host, r.URL, r.Header)
			}
			_, push, err := ws.ReadMessage()
			if err != nil || string(push) != "server-push" {
				t.Fatal("server initiated message lost", err)
			}
			pong := false
			ws.SetPongHandler(func(s string) error { pong = s == "alive"; return nil })
			if err := ws.WriteControl(websocket.PingMessage, []byte("alive"), time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []int{websocket.TextMessage, websocket.BinaryMessage} {
				data := bytes.Repeat([]byte("Motrix live update "), 4096)
				if err := ws.WriteMessage(kind, data); err != nil {
					t.Fatal(err)
				}
				gotKind, got, err := ws.ReadMessage()
				if err != nil || gotKind != kind || !bytes.Equal(data, got) {
					t.Fatal("bidirectional frames broken", err)
				}
			}
			if !pong {
				t.Fatal("ping/pong lost")
			}
			// Removing a listener must close upgraded connections, not leak them
			// beyond shutdown (http.Server.Close alone does not close hijacks).
			engine.apply(Config{})
			if _, _, err := ws.ReadMessage(); err == nil {
				t.Fatal("upgraded connection survived listener removal")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("shutdown did not close upgraded connection")
			}
		})
	}
}

func TestProxyWebSocketOriginGuard(t *testing.T) {
	var called atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Store(true) }))
	defer backend.Close()
	_, host, tlsConfig := testWebProxy(t, backend.URL, true, true, true, false)
	dialer := websocket.Dialer{NetDialContext: proxyTestDial, TLSClientConfig: tlsConfig, HandshakeTimeout: 3 * time.Second}
	for _, origin := range []string{"https://evil.example", "null", "http://" + host} {
		ws, res, err := dialer.Dial("wss://"+host+"/rpc/events", http.Header{"Origin": {origin}})
		if ws != nil {
			ws.Close()
		}
		if res == nil || res.StatusCode != http.StatusForbidden || err == nil {
			t.Fatal("foreign Origin accepted", origin, err)
		}
		res.Body.Close()
	}
	if called.Load() {
		t.Fatal("cross-site handshake reached backend")
	}
}

func TestProxyWebSocketBackendCertificateVerification(t *testing.T) {
	var called atomic.Bool
	backend := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Store(true) }))
	defer backend.Close()
	_, host, tlsConfig := testWebProxy(t, strings.Replace(backend.URL, "https", "wss", 1), true, true, false, false)
	dialer := websocket.Dialer{NetDialContext: proxyTestDial, TLSClientConfig: tlsConfig, HandshakeTimeout: 3 * time.Second}
	ws, res, err := dialer.Dial("wss://"+host+"/rpc/events", nil)
	if ws != nil {
		ws.Close()
	}
	if err == nil || res == nil || res.StatusCode != http.StatusBadGateway {
		t.Fatal("untrusted backend certificate accepted", err)
	}
	res.Body.Close()
	if called.Load() {
		t.Fatal("request reached untrusted TLS backend")
	}
}

func TestProxyWebSocketSharedPort(t *testing.T) {
	backend := func(label string) *httptest.Server {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err := c.WriteMessage(websocket.TextMessage, []byte(label)); err != nil {
				return
			}
			// The default handler acknowledges Close frames. Check that the
			// proxy forwards a normal close handshake, not just data frames.
			c.ReadMessage()
		}))
		t.Cleanup(server.Close)
		return server
	}
	a, b := backend("route-a"), backend("route-b")
	s := testStore(t)
	e := newEngine(s, quiet, newFirewall(false))
	t.Cleanup(e.close)
	addr := freePort(t)
	_, port, _ := net.SplitHostPort(addr)
	cfg := s.snapshot()
	cfg.Rules = []Rule{sharedRule("a", "a.example", addr, a.URL), sharedRule("b", "b.example", addr, strings.Replace(b.URL, "http", "ws", 1))}
	if err := validate(cfg, "127.0.0.1:17880"); err != nil {
		t.Fatal(err)
	}
	e.apply(cfg)
	dialer := websocket.Dialer{NetDialContext: proxyTestDial, HandshakeTimeout: 3 * time.Second}
	for _, item := range []struct{ host, label string }{{"a.example", "route-a"}, {"b.example", "route-b"}} {
		ws, _, err := dialer.Dial("ws://"+net.JoinHostPort(item.host, port)+"/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		ws.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, data, err := ws.ReadMessage()
		if err != nil || string(data) != item.label {
			ws.Close()
			t.Fatal("shared-port route mismatch", err, string(data))
		}
		if err := ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"), time.Now().Add(time.Second)); err != nil {
			ws.Close()
			t.Fatal(err)
		}
		_, _, err = ws.ReadMessage()
		ws.Close()
		if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			t.Fatal("normal close handshake lost", err)
		}
	}
}

func TestProxyWebSocketTargetValidation(t *testing.T) {
	for _, target := range []string{"http://192.0.2.1:8080", "https://192.0.2.1/base", "ws://192.0.2.1:8080/rpc", "wss://192.0.2.1/base"} {
		c := testStore(t).snapshot()
		c.Rules = []Rule{sharedRule("valid", "test.example", "127.0.0.1:18081", target)}
		if err := validate(c, "127.0.0.1:17880"); err != nil {
			t.Errorf("valid target %s: %v", target, err)
		}
	}
	for _, target := range []string{"ftp://192.0.2.1", "wss://user:pass@192.0.2.1", "ws://192.0.2.1/?token=secret", "wss://192.0.2.1/#fragment", "ws://127.0.0.1:18081", "wss://", "ws:///path"} {
		c := testStore(t).snapshot()
		c.Rules = []Rule{sharedRule("invalid", "test.example", "127.0.0.1:18081", target)}
		if err := validate(c, "127.0.0.1:17880"); err == nil {
			t.Errorf("unsafe target accepted: %s", target)
		}
	}
	// Scheme aliasing must also use the correct default port for loop checks.
	c := testStore(t).snapshot()
	c.Rules = []Rule{sharedRule("loop", "test.example", "127.0.0.1:443", "wss://127.0.0.1")}
	if err := validate(c, "127.0.0.1:17880"); err == nil {
		t.Fatal("wss default-port loop accepted")
	}
}
