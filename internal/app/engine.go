package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"linknest/internal/access"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

type RuleStatus struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Message string `json:"message"`
}
type running struct {
	rule   Rule
	stop   func()
	status RuleStatus
}
type Engine struct {
	access    *access.Manager
	mu        sync.Mutex
	store     *Store
	rules     map[string]*running
	log       func(string, string)
	fw        *Firewall
	webGroups map[string]*webRunning
	portal    *Portal
}

func newEngine(s *Store, log func(string, string), fw *Firewall) *Engine {
	e := &Engine{store: s, access: access.New(filepath.Join(s.dir, "access")), rules: map[string]*running{}, webGroups: map[string]*webRunning{}, log: log, fw: fw, portal: newPortal(s, log)}
	c := s.snapshot()
	e.access.Configure(c.Access, c.Whitelist)
	return e
}
func (e *Engine) statuses() []RuleStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []RuleStatus{}
	for _, r := range e.rules {
		out = append(out, r.status)
	}
	return out
}
func (e *Engine) apply(c Config) {
	migrateConfig(&c)
	e.access.Configure(c.Access, c.Whitelist)
	e.mu.Lock()
	defer e.mu.Unlock()
	desired := map[string]Rule{}
	groups := map[string][]Rule{}
	webErrors := map[string]error{}
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		desired[r.ID] = r
		if r.Kind != "web" {
			continue
		}
		if r.TLS {
			if _, err := e.loadWebCertificate(r.Certificate); err != nil {
				webErrors[r.ID] = fmt.Errorf("TLS 证书未就绪：%w", err)
			}
		}
		// Keep failed domains reserved: never fall through to another owner's
		// wildcard/default route when a certificate is unavailable.
		key := webListenKey(r)
		groups[key] = append(groups[key], r)
	}
	// Close removed listeners before opening replacements, including web ↔ TCP.
	for key, listener := range e.webGroups {
		if _, ok := groups[key]; !ok {
			listener.stop()
			delete(e.webGroups, key)
		}
	}
	for id, running := range e.rules {
		next, ok := desired[id]
		if !ok || next.Kind != "web" && !reflect.DeepEqual(next, running.rule) || next.Kind != running.rule.Kind || running.status.State == "error" {
			if running.stop != nil {
				running.stop()
			}
			delete(e.rules, id)
		}
	}
	for id, r := range desired {
		if r.Kind == "web" {
			continue
		}
		if _, ok := e.rules[id]; ok {
			continue
		}
		rr := &running{rule: r, status: RuleStatus{ID: id, State: "running", Message: "监听正常"}}
		var stop func()
		var err error
		if r.ForwardMode != "kernel" {
			stop, err = e.start(r)
		}
		if err != nil {
			rr.status.State = "error"
			rr.status.Message = err.Error()
			e.log("error", r.Name+"："+err.Error())
		} else {
			rr.stop = stop
			e.log("info", r.Name+" 已启动（"+r.Listen+"）")
		}
		e.rules[id] = rr
	}
	for key, rules := range groups {
		listener := e.webGroups[key]
		var err error
		if listener == nil {
			listener, err = e.startWebGroup(rules)
			if err == nil {
				e.webGroups[key] = listener
				e.log("info", "反向代理监听已启动（"+rules[0].Listen+"）")
			}
		} else {
			// Publish the complete domain/owner/TLS table in one atomic swap.
			listener.ref.Store(newWebSnapshot(rules))
		}
		for _, r := range rules {
			rr := e.rules[r.ID]
			if rr == nil {
				rr = &running{}
				e.rules[r.ID] = rr
			}
			rr.rule = r
			rr.status = RuleStatus{ID: r.ID, State: "running", Message: "监听正常"}
			if len(rules) > 1 {
				rr.status.Message = fmt.Sprintf("监听正常 · %d 条主规则共享端口", len(rules))
			}
			if err != nil {
				rr.status.State = "error"
				rr.status.Message = err.Error()
			}
		}
		if err != nil {
			e.log("error", "反向代理监听失败："+err.Error())
		}
	}
	for id, err := range webErrors {
		e.rules[id] = &running{rule: desired[id], status: RuleStatus{ID: id, State: "error", Message: err.Error()}}
	}
	active := []Rule{}
	for _, rr := range e.rules {
		if rr.status.State == "running" {
			active = append(active, rr.rule)
		}
	}
	e.fw.sync(sharedFirewallRules(active), c)
	if err := e.fw.syncKernel(active, c); err != nil {
		for _, rr := range e.rules {
			if rr.rule.ForwardMode == "kernel" {
				rr.status.State = "error"
				rr.status.Message = "内核转发未生效：" + err.Error()
			}
		}
	} else {
		for _, rr := range e.rules {
			if rr.rule.ForwardMode == "kernel" {
				rr.status.Message = "IPv4 内核 NAT 转发已生效"
			}
		}
	}
}
func (e *Engine) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, listener := range e.webGroups {
		listener.stop()
		delete(e.webGroups, key)
	}
	for _, r := range e.rules {
		if r.stop != nil {
			r.stop()
		}
	}
	e.rules = map[string]*running{}
	e.fw.cleanup()
	if err := e.access.Flush(); err != nil {
		e.log("error", "封禁记录保存失败："+err.Error())
	}
}
func (e *Engine) allowed(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	return err == nil && !e.store.blockedIP(net.ParseIP(h)) && !e.access.Blocked(access.Address(addr))
}
func (e *Engine) start(r Rule) (func(), error) {
	if r.Kind == "tcpudp" {
		tcp := r
		tcp.Kind = "tcp"
		stopTCP, err := e.start(tcp)
		if err != nil {
			return nil, err
		}
		udp := r
		udp.Kind = "udp"
		stopUDP, err := e.startUDP(udp)
		if err != nil {
			stopTCP()
			return nil, err
		}
		return func() { stopTCP(); stopUDP() }, nil
	}
	if r.Kind == "web" {
		return e.startWeb(r)
	}
	if r.Kind == "udp" {
		return e.startUDP(r)
	}
	ln, err := net.Listen(listenNetwork(r, "tcp"), r.Listen)
	if err != nil {
		return nil, err
	}
	if r.Kind == "tcp" {
		ctx, cancel := context.WithCancel(context.Background())
		var active sync.Map
		slots := make(chan struct{}, 128)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				if !e.allowed(c.RemoteAddr().String()) {
					c.Close()
					continue
				}
				select {
				case slots <- struct{}{}:
				default:
					c.Close()
					continue
				}
				active.Store(c, true)
				go func() {
					defer func() { <-slots }()
					defer active.Delete(c)
					defer c.Close()
					d := net.Dialer{Timeout: 8 * time.Second}
					out, err := d.DialContext(ctx, "tcp", r.Target)
					if err != nil {
						return
					}
					defer out.Close()
					active.Store(out, true)
					defer active.Delete(out)
					done := make(chan struct{}, 1)
					go func() {
						io.Copy(out, c)
						if t, ok := out.(*net.TCPConn); ok {
							t.CloseWrite()
						}
						done <- struct{}{}
					}()
					io.Copy(c, out)
					c.Close()
					out.Close()
					<-done
				}()
			}
		}()
		return func() { cancel(); ln.Close(); active.Range(func(k, v any) bool { k.(net.Conn).Close(); return true }) }, nil
	}
	return func() { ln.Close() }, nil
}

func (e *Engine) startUDP(r Rule) (func(), error) {
	addr, err := net.ResolveUDPAddr("udp", r.Listen)
	if err != nil {
		return nil, err
	}
	up, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUDP(listenNetwork(r, "udp"), addr)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	peers := map[string]*net.UDPConn{}
	closed := false
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !e.allowed(src.String()) {
				continue
			}
			key := src.String()
			mu.Lock()
			if closed {
				mu.Unlock()
				return
			}
			conn := peers[key]
			if conn == nil && len(peers) < 128 {
				conn, err = net.DialUDP("udp", nil, up)
				if err == nil {
					peers[key] = conn
					client := *src
					go func(c *net.UDPConn) {
						defer c.Close()
						defer func() {
							mu.Lock()
							if peers[key] == c {
								delete(peers, key)
							}
							mu.Unlock()
						}()
						data := make([]byte, 65535)
						for {
							c.SetReadDeadline(time.Now().Add(60 * time.Second))
							n, er := c.Read(data)
							if er != nil {
								return
							}
							if e.allowed(client.String()) {
								ln.WriteToUDP(data[:n], &client)
							}
						}
					}(conn)
				}
			}
			mu.Unlock()
			if conn != nil {
				conn.Write(buf[:n])
			}
		}
	}()
	return func() {
		ln.Close()
		mu.Lock()
		closed = true
		for _, c := range peers {
			c.Close()
		}
		mu.Unlock()
	}, nil
}

func wake(d Device) error {
	m, err := parseWOLMAC(d.MAC)
	if err != nil {
		return err
	}
	ip := net.ParseIP(d.Broadcast)
	if ip == nil || ip.To4() == nil {
		return errors.New("广播地址无效")
	}
	packet := []byte{255, 255, 255, 255, 255, 255}
	for i := 0; i < 16; i++ {
		packet = append(packet, m...)
	}
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: 9})
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = c.Write(packet)
	return err
}
