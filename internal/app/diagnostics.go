package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type diagnosticCache struct {
	mu       sync.Mutex
	running  bool
	checked  time.Time
	values   map[string]any
	backends sync.Map
	slots    chan struct{}
}

func (d *diagnosticCache) snapshot() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.values == nil {
		return map[string]any{"state": "unchecked", "message": "运行环境尚未检查", "refreshing": d.running}
	}
	out := map[string]any{}
	for k, v := range d.values {
		out[k] = v
	}
	out["refreshing"] = d.running
	return out
}
func (d *diagnosticCache) refresh(f *Firewall) {
	d.mu.Lock()
	if d.running || time.Since(d.checked) < 30*time.Second {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.mu.Unlock()
	go func() {
		values := map[string]any{"state": "checked", "os": runtime.GOOS, "architecture": runtime.GOARCH, "networkMode": "未确认（请核对 Docker 网络模式）", "firewallAuthorized": f.enabled}
		if mode := os.Getenv("LINKNEST_NETWORK_MODE"); mode != "" {
			values["networkMode"] = mode + "（部署声明）"
		}
		capAdmin, capRaw := false, false
		if b, e := os.ReadFile("/proc/self/status"); e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "CapEff:") {
					v, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
					capAdmin = v&(1<<12) != 0
					capRaw = v&(1<<13) != 0
				}
			}
		}
		values["netAdmin"] = capAdmin
		values["netRaw"] = capRaw
		values["xtablesLock"] = "不可读写或不存在"
		if file, e := os.OpenFile("/run/xtables.lock", os.O_RDWR, 0); e == nil {
			file.Close()
			values["xtablesLock"] = "可读写（共享挂载需核对部署参数）"
		}
		families := map[string]any{}
		for _, v6 := range []bool{false, true} {
			family, path := "ipv4", "/proc/sys/net/ipv4/ip_forward"
			if v6 {
				family = "ipv6"
				path = "/proc/sys/net/ipv6/conf/all/forwarding"
			}
			bin, _, _ := kernelTools(v6)
			entry := map[string]any{"filter": "未确认", "nat": "未确认", "forwarding": "未确认", "backend": "未确认"}
			if b, e := os.ReadFile(path); e == nil {
				entry["forwarding"] = strings.TrimSpace(string(b)) == "1"
			}
			if runtime.GOOS == "linux" {
				if output, e := command(bin, []string{"--version"}, ""); e == nil {
					entry["backend"] = strings.TrimSpace(output)
				} else {
					entry["backend"] = e.Error()
				}
				if capAdmin && capRaw {
					for _, table := range []string{"filter", "nat"} {
						if _, e := command(bin, []string{"-w", "1", "-t", table, "-S"}, ""); e == nil {
							entry[table] = "可读取"
						} else {
							entry[table] = e.Error()
						}
					}
				}
			}
			families[family] = entry
		}
		values["families"] = families
		values["checked"] = time.Now().Format(time.RFC3339)
		d.mu.Lock()
		d.values = values
		d.checked = time.Now()
		d.running = false
		d.mu.Unlock()
	}()
}

type backendResult struct {
	revision string
	part     StatusPart
}

func (a *App) ruleStatuses(revision string) []RuleStatus {
	list := a.engine.statuses()
	for i := range list {
		if value, ok := a.diagnostics.backends.Load(list[i].ID); ok {
			result := value.(backendResult)
			if result.revision == revision {
				list[i].Backend = result.part
			}
		}
	}
	return list
}
func (a *App) checkBackend(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &q) {
		return
	}
	a.diagnostics.mu.Lock()
	if a.diagnostics.slots == nil {
		a.diagnostics.slots = make(chan struct{}, 2)
	}
	slots := a.diagnostics.slots
	a.diagnostics.mu.Unlock()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		fail(w, 429, "已有检查正在运行")
		return
	}
	cfg, revision := a.store.snapshotRevision()
	var rule *Rule
	for _, v := range cfg.Rules {
		if v.ID == q.ID {
			copy := v
			rule = &copy
			break
		}
	}
	if rule == nil {
		fail(w, 404, "规则不存在")
		return
	}
	result := StatusPart{State: "reachable", Message: "TCP 连接可达；不代表应用或公网访问正常"}
	type target struct {
		address, serverName string
		tls, skip           bool
	}
	targets := []target{}
	if rule.Kind == "udp" {
		result = StatusPart{State: "unchecked", Message: "UDP 无通用握手，需使用实际业务验证"}
	} else if rule.Kind != "web" {
		targets = append(targets, target{address: rule.Target})
	} else {
		for _, route := range rule.Routes {
			if !route.Enabled || route.Backend == "bookmarks" || route.Backend == "wol" {
				continue
			}
			u, e := proxyTargetURL(route.Target)
			if e != nil {
				continue
			}
			port := u.Port()
			if port == "" {
				port = "80"
				if u.Scheme == "https" {
					port = "443"
				}
			}
			targets = append(targets, target{address: net.JoinHostPort(u.Hostname(), port), serverName: u.Hostname(), tls: u.Scheme == "https", skip: route.SkipTLSVerify})
		}
		if len(targets) == 0 {
			result = StatusPart{State: "unchecked", Message: "没有需要检查的外部后端"}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	for _, t := range targets {
		dial := net.Dialer{Timeout: 3 * time.Second}
		conn, e := dial.DialContext(ctx, "tcp", t.address)
		if e == nil {
			if t.tls {
				secure := tls.Client(conn, &tls.Config{ServerName: t.serverName, MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.skip})
				e = secure.HandshakeContext(ctx)
			}
			conn.Close()
		}
		if e != nil {
			result = StatusPart{State: "error", Message: fmt.Sprintf("%s 连接失败：%v", t.address, e)}
			break
		}
	}
	result.Message += " · " + time.Now().Format(time.RFC3339)
	a.diagnostics.backends.Store(q.ID, backendResult{revision: revision, part: result})
	respond(w, 200, map[string]any{"ok": true, "backend": result})
}
