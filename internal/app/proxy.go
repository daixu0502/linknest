package app

import (
	"context"
	"crypto/tls"
	"errors"
	"linknest/internal/access"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type proxyConnectionKey struct{}

// Exact domain > longest wildcard suffix > explicit catch-all. Unknown hosts
// never fall through to an unrelated backend.
func matchRoute(routes []WebRoute, host string) *WebRoute {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = routeDomainKey(host)
	var best *WebRoute
	score := -1
	for i := range routes {
		r := &routes[i]
		if !r.Enabled {
			continue
		}
		domains := r.Domains
		if len(domains) == 0 {
			domains = []string{"*"}
		}
		for _, d := range domains {
			d = routeDomainKey(d)
			n := -1
			if d == "*" {
				n = 0
			} else if d == host {
				n = 10000 + len(d)
			} else if strings.HasPrefix(d, "*.") && strings.HasSuffix(host, d[1:]) && len(host) > len(d)-1 {
				n = len(d)
			}
			if n > score {
				best = r
				score = n
			}
		}
	}
	return best
}
func (e *Engine) startWeb(r Rule) (func(), error) {
	c := Config{Rules: []Rule{r}}
	migrateConfig(&c)
	r = c.Rules[0]
	if r.TLS {
		if _, err := e.loadWebCertificate(r.Certificate); err != nil {
			return nil, err
		}
	}
	group, err := e.startWebGroup([]Rule{r})
	if err != nil {
		return nil, err
	}
	return group.stop, nil
}

func (e *Engine) loadWebCertificate(id string) (*tls.Certificate, error) {
	if !validID.MatchString(id) {
		return nil, errors.New("证书标识无效")
	}
	b, err := os.ReadFile(filepath.Join(e.store.dir, "certificates", id+".pem"))
	if err != nil {
		return nil, err
	}
	p, err := tls.X509KeyPair(b, b)
	return &p, err
}

func (e *Engine) startWebGroup(rules []Rule) (*webRunning, error) {
	r := rules[0]
	ln, err := net.Listen(listenNetwork(r, "tcp"), r.Listen)
	if err != nil {
		return nil, err
	}
	ref := &atomic.Pointer[webSnapshot]{}
	ref.Store(newWebSnapshot(rules))
	transport := func(skip bool) *http.Transport {
		return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxIdleConns: 64, IdleConnTimeout: 60 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: skip}}
	}
	verified, insecure := transport(false), transport(true)
	var connections sync.Map
	var connectionRoutes sync.Map
	var routeMu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if !e.allowed(q.RemoteAddr) {
			http.Error(w, "Access denied", 403)
			return
		}
		observed := &access.Response{ResponseWriter: &upgradeResponse{ResponseWriter: w, connections: &connections, onClose: func(c net.Conn) { connectionRoutes.Delete(c) }}}
		w = observed
		defer func() { e.access.Observe(q.RemoteAddr, q.URL.Path, observed.Status) }()
		routeMu.Lock()
		snapshot := ref.Load()
		route, knownHost := matchRoutePath(snapshot.routes, q.Host, q.URL.Path)
		current := Rule{}
		if route != nil {
			current = snapshot.owners[route.ID]
			if conn, ok := q.Context().Value(proxyConnectionKey{}).(net.Conn); ok {
				connectionRoutes.Store(conn, route.ID)
			}
		}
		routeMu.Unlock()
		if route == nil {
			if knownHost {
				http.Error(w, "此路径未匹配到已启用的子规则", http.StatusNotFound)
				return
			}
			http.Error(w, "未匹配到已启用的反向代理子规则（Host not allowed）。\n请使用子规则中配置的完整域名和此监听端口。直接访问 IP 或其他域名不会自动进入轻面板 / WOL；如需使用，请在管理后台将该域名或 IP 明确添加到对应子规则。", 421)
			return
		}
		if current.TLS {
			if _, err := e.loadWebCertificate(current.Certificate); err != nil {
				http.Error(w, "此入口的 TLS 证书暂不可用", http.StatusServiceUnavailable)
				return
			}
		}
		if q.TLS != nil {
			if !current.TLS {
				http.Error(w, "此入口未启用 HTTPS", 421)
				return
			}
			if q.TLS.ServerName != "" {
				_, tlsOwner := snapshot.match(q.TLS.ServerName)
				if tlsOwner.ID != current.ID {
					http.Error(w, "TLS 主机名与请求入口不一致", 421)
					return
				}
			}
		}
		if current.TLS && q.TLS == nil {
			if !current.RedirectHTTP {
				http.Error(w, "请使用 HTTPS 访问此入口", http.StatusBadRequest)
				return
			}
			if q.Host == "" || strings.ContainsAny(q.Host, "/\\?#@\r\n") {
				http.Error(w, "无效主机名", 400)
				return
			}
			u := url.URL{Scheme: "https", Host: q.Host, Path: q.URL.Path, RawPath: q.URL.RawPath, RawQuery: q.URL.RawQuery}
			http.Redirect(w, q, u.String(), http.StatusTemporaryRedirect)
			return
		}
		if route.Backend == "bookmarks" || route.Backend == "wol" {
			e.portal.serve(*route, w, q)
			return
		}
		u, err := proxyTargetURL(route.Target)
		if err != nil {
			http.Error(w, "Invalid backend", 502)
			return
		}
		tr := verified
		if route.SkipTLSVerify {
			tr = insecure
		}
		if route.RewriteOrigin && !proxySourceAllowed(q) {
			http.Error(w, "来源兼容模式仅接受此入口的同源请求", http.StatusForbidden)
			return
		}
		proxy := httputil.ReverseProxy{Transport: tr, Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(u)
			// Rewrite drops untrusted forwarding headers; derive these from the
			// actual client connection, including TLS-terminated WebSocket upgrades.
			p.SetXForwarded()
			if route.PreserveHost {
				p.Out.Host = p.In.Host
			}
			if route.RewriteOrigin {
				host := u.Host
				if route.PreserveHost {
					host = p.In.Host
				}
				if p.In.Header.Get("Origin") != "" {
					p.Out.Header.Set("Origin", u.Scheme+"://"+host)
				}
				if raw := p.In.Header.Get("Referer"); raw != "" {
					referer, _ := url.Parse(raw)
					referer.Scheme, referer.Host = u.Scheme, host
					p.Out.Header.Set("Referer", referer.String())
				}
			}
		}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { http.Error(w, "上游暂不可达", 502) }}
		proxy.ServeHTTP(w, q)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, proxyConnectionKey{}, c)
	}, ConnState: func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Store(conn, true)
		}
		if state == http.StateClosed {
			connections.Delete(conn)
			connectionRoutes.Delete(conn)
		}
	}}
	// Always classify both protocols so adding/removing TLS owners is hot-updatable.
	ln = newMixedListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		snapshot := ref.Load()
		if hello.ServerName != "" {
			route, owner := snapshot.match(hello.ServerName)
			if route == nil || !owner.TLS {
				return nil, errors.New("该域名未启用 TLS")
			}
			return e.loadWebCertificate(owner.Certificate)
		}
		// IP clients may omit SNI. Only a single certificate is unambiguous.
		id := ""
		for _, owner := range snapshot.rules {
			if !owner.TLS {
				continue
			}
			if id != "" && id != owner.Certificate {
				return nil, errors.New("多个证书共用端口时需要 SNI")
			}
			id = owner.Certificate
		}
		return e.loadWebCertificate(id)
	}})
	go func() {
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			e.log("error", r.Name+" 监听已退出")
		}
	}()
	return &webRunning{ref: ref, reconcile: func(next *webSnapshot) {
		routeMu.Lock()
		defer routeMu.Unlock()
		ref.Store(next)
		active := map[string]bool{}
		for _, route := range next.routes {
			if route.Enabled {
				active[route.ID] = true
			}
		}
		connectionRoutes.Range(func(k, v any) bool {
			if !active[v.(string)] {
				k.(net.Conn).Close()
				connectionRoutes.Delete(k)
			}
			return true
		})
	}, stop: func() {
		server.Close()
		connections.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		verified.CloseIdleConnections()
		insecure.CloseIdleConnections()
	}}, nil
}

// WebSocket handshakes travel over HTTP/1.1. ReverseProxy handles Upgrade,
// subprotocol negotiation and the full-duplex tunnel without a separate switch.
// Accept explicit ws/wss targets as aliases, keeping HTTP transport TLS checks
// and the same URL validation for configuration and runtime requests.
func proxyTargetURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("后端地址需为不含账号、查询参数或片段的 HTTP/HTTPS/WS/WSS 地址")
	}
	switch u.Scheme {
	case "http", "https":
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	default:
		return nil, errors.New("后端地址仅支持 HTTP/HTTPS/WS/WSS")
	}
	return u, nil
}

func originAddress(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// Validate at the public boundary BEFORE rewriting. Never turn a foreign/null
// Origin into a trusted upstream Origin, including WebSocket handshakes.
func proxySourceAllowed(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	expected := &url.URL{Scheme: scheme, Host: r.Host}
	for _, name := range []string{"Origin", "Referer"} {
		values := r.Header.Values(name)
		if len(values) > 1 {
			return false
		}
		if len(values) == 0 {
			continue
		}
		u, err := url.Parse(values[0])
		if err != nil || u.User != nil || u.Scheme != scheme || u.Host == "" || originAddress(u) != originAddress(expected) {
			return false
		}
		if name == "Origin" && (u.Path != "" || u.RawQuery != "" || u.Fragment != "") {
			return false
		}
	}
	return true
}
