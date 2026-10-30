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
	"sync/atomic"
	"time"
)

type RuleStatus struct {
	ID       string         `json:"id"`
	State    string         `json:"state"`
	Message  string         `json:"message"`
	Listener StatusPart     `json:"listener"`
	Firewall StatusPart     `json:"firewall"`
	Backend  StatusPart     `json:"backend"`
	Traffic  *TrafficStatus `json:"traffic,omitempty"`
}
type StatusPart struct {
	State   string `json:"state"`
	Message string `json:"message"`
}
type TrafficStatus struct {
	Active   int64 `json:"active"`
	Capacity int   `json:"capacity"`
	Dropped  int64 `json:"dropped"`
}
type forwardCounters struct {
	active   atomic.Int64
	dropped  atomic.Int64
	capacity atomic.Int64
}
type running struct {
	rule   Rule
	stop   func()
	status RuleStatus
}
type Engine struct {
	statusCache atomic.Pointer[[]RuleStatus]
	traffic     sync.Map
	access      *access.Manager
	mu          sync.Mutex
	store       *Store
	rules       map[string]*running
	log         func(string, string)
	fw          *Firewall
	webGroups   map[string]*webRunning
	portal      *Portal
}

func newEngine(s *Store, log func(string, string), fw *Firewall) *Engine {
	e := &Engine{store: s, access: access.New(filepath.Join(s.dir, "access")), rules: map[string]*running{}, webGroups: map[string]*webRunning{}, log: log, fw: fw, portal: newPortal(s, log)}
	c := s.snapshot()
	e.access.Configure(c.Access, c.Whitelist)
	return e
}
func (e *Engine) statuses() []RuleStatus {
	out := []RuleStatus{}
	if cached := e.statusCache.Load(); cached != nil {
		out = append(out, (*cached)...)
	}
	for i := range out {
		if value, ok := e.traffic.Load(out[i].ID); ok {
			v := value.(*forwardCounters)
			out[i].Traffic = &TrafficStatus{Active: v.active.Load(), Capacity: int(v.capacity.Load()), Dropped: v.dropped.Load()}
		}
	}
	return out
}
func (e *Engine) counters(id string) *forwardCounters {
	value, _ := e.traffic.LoadOrStore(id, &forwardCounters{})
	return value.(*forwardCounters)
}

// Called with engine.mu held, after a complete application. Readers never wait
// on iptables, bind, DNS or certificate disk operations.
func (e *Engine) publishStatuses() {
	out := []RuleStatus{}
	fw := e.fw.get()
	for _, rr := range e.rules {
		if value, ok := e.traffic.Load(rr.rule.ID); ok {
			capacity := int64(128)
			if rr.rule.Kind == "tcpudp" {
				capacity = 256
			}
			value.(*forwardCounters).capacity.Store(capacity)
		}
		s := rr.status
		s.Listener = StatusPart{State: s.State, Message: s.Message}
		if rr.rule.ForwardMode == "kernel" {
			s.Listener = StatusPart{State: "not_applicable", Message: "内核 NAT 不创建监听 socket"}
		}
		s.Backend = StatusPart{State: "unchecked", Message: "未检查"}
		s.Firewall = StatusPart{State: "unmanaged", Message: "未启用自动放行"}
		if rr.rule.OpenFirewall {
			s.Firewall = StatusPart{State: "disabled", Message: "未授权防火墙管理"}
			if fw.Enabled {
				s.Firewall = StatusPart{State: "applied", Message: "所需地址族已放行"}
				if rr.rule.ForwardMode == "kernel" {
					if s.State == "error" {
						s.Firewall = StatusPart{State: "error", Message: s.Message}
					}
				} else {
					for _, v6 := range []bool{false, true} {
						if _, ok := listenerAddress(rr.rule, v6); ok {
							key := "ipv4"
							if v6 {
								key = "ipv6"
							}
							part, exists := fw.Families[key]
							if !exists || part.State != "applied" {
								s.Firewall = StatusPart{State: "error", Message: part.Message}
								if s.Firewall.Message == "" {
									s.Firewall.Message = fw.Message
								}
							}
						}
					}
				}
			}
		}
		out = append(out, s)
	}
	e.statusCache.Store(&out)
}
func (e *Engine) apply(c Config) {
	migrateConfig(&c)
	e.access.Configure(c.Access, c.Whitelist)
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.publishStatuses()
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
	conflicts := e.fw.forwardConflicts(c.Rules)
	for key, listener := range e.webGroups {
		if _, ok := groups[key]; !ok {
			listener.stop()
			delete(e.webGroups, key)
		}
	}
	for id, running := range e.rules {
		next, ok := desired[id]
		if !ok || next.Kind != "web" && !reflect.DeepEqual(next, running.rule) || next.Kind != running.rule.Kind || running.status.State == "error" && conflicts[id] == nil {
			if running.stop != nil {
				running.stop()
			}
			delete(e.rules, id)
			e.traffic.Delete(id)
		}
	}
	for id, err := range conflicts {
		old := e.rules[id]
		if old == nil || old.status.Message != err.Error() {
			e.log("error", desired[id].Name+"："+err.Error())
		}
		if old != nil && old.stop != nil {
			old.stop()
		}
		e.rules[id] = &running{rule: desired[id], status: RuleStatus{ID: id, State: "error", Message: err.Error()}}
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
		} else {
			// Isolate local listener/config errors before publishing the shared
			// kernel batch, so one bad port does not take healthy rules down.
			err = kernelRuleReady(r)
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
			listener.reconcile(newWebSnapshot(rules))
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
	kernelErrors := e.fw.syncKernelByRule(active, c)
	for id, rr := range e.rules {
		if rr.rule.ForwardMode == "kernel" && rr.status.State == "running" {
			if err := kernelErrors[id]; err != nil {
				rr.status.State = "error"
				rr.status.Message = "内核转发未生效：" + err.Error()
			} else {
				_, _, family := kernelTools(rr.rule.Network == "ipv6")
				rr.status.Message = family + " 内核 NAT 转发已生效"
				if rr.rule.PreserveClientIP {
					rr.status.Message += " · 保留客户端 IP"
				}
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
		stats := e.counters(r.ID)
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
					stats.active.Add(1)
				default:
					stats.dropped.Add(1)
					c.Close()
					continue
				}
				active.Store(c, true)
				go func() {
					defer func() { <-slots; stats.active.Add(-1) }()
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
	ctx, cancel := context.WithCancel(context.Background())
	target := udpTarget{raw: r.Target}
	stats := e.counters(r.ID)
	ln, err := net.ListenUDP(listenNetwork(r, "udp"), addr)
	if err != nil {
		cancel()
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
				mu.Unlock()
				up, resolveErr := target.get(ctx)
				mu.Lock()
				if closed {
					mu.Unlock()
					return
				}
				if resolveErr != nil {
					stats.dropped.Add(1)
					mu.Unlock()
					continue
				}
				conn, err = net.DialUDP("udp", nil, up)
				if err == nil {
					peers[key] = conn
					stats.active.Add(1)
					conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					client := *src
					go func(c *net.UDPConn) {
						defer c.Close()
						defer stats.active.Add(-1)
						defer func() {
							mu.Lock()
							if peers[key] == c {
								delete(peers, key)
							}
							mu.Unlock()
						}()
						data := make([]byte, 65535)
						for {
							n, er := c.Read(data)
							if er != nil {
								return
							}
							c.SetReadDeadline(time.Now().Add(60 * time.Second))
							if e.allowed(client.String()) {
								ln.WriteToUDP(data[:n], &client)
							}
						}
					}(conn)
				}
			}
			mu.Unlock()
			if conn != nil {
				conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Write(buf[:n]); err != nil {
					stats.dropped.Add(1)
				}
			} else {
				stats.dropped.Add(1)
			}
		}
	}()
	return func() {
		cancel()
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
