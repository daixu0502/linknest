package app

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type AdminTLSConfig struct {
	Enabled     bool   `json:"enabled"`
	Redirect    bool   `json:"redirect"`
	Certificate string `json:"certificate"`
}

func (a *App) adminCertificate(cfg AdminTLSConfig) (*tls.Certificate, error) {
	if !cfg.Enabled {
		return nil, errors.New("管理 HTTPS 未启用")
	}
	if !validID.MatchString(cfg.Certificate) {
		return nil, errors.New("请选择管理 HTTPS 证书")
	}
	b, e := os.ReadFile(filepath.Join(a.store.dir, "certificates", cfg.Certificate+".pem"))
	if e != nil {
		return nil, errors.New("管理 HTTPS 证书文件不存在")
	}
	p, e := tls.X509KeyPair(b, b)
	if e != nil {
		return nil, errors.New("管理 HTTPS 证书与私钥不匹配")
	}
	leaf, e := x509.ParseCertificate(p.Certificate[0])
	if e != nil {
		return nil, e
	}
	if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
		return nil, errors.New("管理 HTTPS 证书不在有效期内")
	}
	p.Leaf = leaf
	return &p, nil
}
func (a *App) adminTLSStatus() map[string]any {
	c := a.store.snapshot().AdminTLS
	_, e := a.adminCertificate(c)
	message := "HTTP / HTTPS 同端口已就绪，新连接读取所选证书"
	if e != nil {
		message = e.Error()
	}
	return map[string]any{"ready": e == nil, "message": message}
}
func (a *App) redirectAdmin(w http.ResponseWriter, r *http.Request) bool {
	c := a.store.snapshot().AdminTLS
	if r.TLS != nil || !c.Enabled || !c.Redirect || r.URL.Path == "/api/health" {
		return false
	}
	if _, err := a.adminCertificate(c); err != nil {
		return false
	} // Keep HTTP available if certificate is lost/expired.
	if r.Host == "" || strings.ContainsAny(r.Host, "/\\?#@\r\n") {
		http.Error(w, "无效主机名", 400)
		return true
	}
	u := url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
	return true
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// Classification happens concurrently with a bounded number of workers, so an
// idle connection cannot block all HTTP/TLS accepts on the shared port.
type mixedListener struct {
	net.Listener
	ready  chan net.Conn
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	active sync.Map
	config *tls.Config
}

func newMixedListener(base net.Listener, cfg *tls.Config) *mixedListener {
	m := &mixedListener{Listener: base, ready: make(chan net.Conn), done: make(chan struct{}), config: cfg}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		slots := make(chan struct{}, 64)
		for {
			c, e := base.Accept()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				c.Close()
				continue
			}
			m.active.Store(c, true)
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				defer func() { <-slots; m.active.Delete(c) }()
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(c)
				first, e := reader.Peek(1)
				if e != nil {
					c.Close()
					return
				}
				c.SetReadDeadline(time.Time{})
				var wrapped net.Conn = &bufferedConn{Conn: c, reader: reader}
				if first[0] == 0x16 {
					wrapped = tls.Server(wrapped, m.config)
				}
				select {
				case m.ready <- wrapped:
				case <-m.done:
					c.Close()
				}
			}()
		}
	}()
	return m
}
func (m *mixedListener) Accept() (net.Conn, error) {
	select {
	case c := <-m.ready:
		return c, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}
func (m *mixedListener) Close() error {
	var e error
	m.once.Do(func() {
		close(m.done)
		e = m.Listener.Close()
		m.active.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		m.wg.Wait()
	})
	return e
}
func (a *App) adminListener() (net.Listener, error) {
	l, e := net.Listen("tcp", a.admin)
	if e != nil {
		return nil, e
	}
	return newMixedListener(l, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return a.adminCertificate(a.store.snapshot().AdminTLS)
	}}), nil
}
