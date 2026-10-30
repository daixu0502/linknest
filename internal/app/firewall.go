package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Only these application-owned chains are ever flushed. Never flush INPUT, UCI, or Docker chains.
const fwChain = "LNEST_IN"

type FWStatus struct {
	Families map[string]StatusPart `json:"families"`
	Checked  string                `json:"checked"`
	Enabled  bool                  `json:"enabled"`
	State    string                `json:"state"`
	Message  string                `json:"message"`
	Ports    []string              `json:"ports"`
}
type Firewall struct {
	cache    atomic.Pointer[FWStatus]
	mu       sync.Mutex
	enabled  bool
	status   FWStatus
	run      func(string, []string, string) (string, error)
	readFile func(string) ([]byte, error)
}

func command(name string, args []string, input string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Stdin = strings.NewReader(input)
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s 失败：%s", name, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
func newFirewall(enabled bool) *Firewall {
	return &Firewall{enabled: enabled, status: FWStatus{Enabled: enabled, State: "disabled", Message: "未授权防火墙管理；应用层 IP 过滤仍生效", Ports: []string{}}, run: command, readFile: os.ReadFile}
}
func (f *Firewall) get() FWStatus {
	if s := f.cache.Load(); s != nil {
		return *s
	}
	return FWStatus{Enabled: f.enabled, State: "disabled", Message: "尚未同步防火墙", Ports: []string{}, Families: map[string]StatusPart{}}
}
func familyMatch(s string, v6 bool) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		ip, _, _ = net.ParseCIDR(s)
	}
	return ip != nil && (ip.To4() == nil) == v6
}
func ruleProtocols(r Rule) []string {
	if r.Kind == "tcpudp" {
		return []string{"tcp", "udp"}
	}
	if r.Kind == "udp" {
		return []string{"udp"}
	}
	return []string{"tcp"}
}
func buildFirewall(rules []Rule, c Config, v6 bool) string {
	var b strings.Builder
	b.WriteString("*filter\n-F " + fwChain + "\n")
	// Whitelisted clients bypass only this application's deny list, not the router's firewall.
	for _, r := range rules {
		if r.ForwardMode == "kernel" {
			continue
		}
		if (r.Network == "ipv4" && v6) || (r.Network == "ipv6" && !v6) {
			continue
		}
		h, p, _ := hostPort(r.Listen)
		ip := net.ParseIP(h)
		if ip != nil && ip.To4() != nil && v6 {
			continue
		}
		if ip != nil && !ip.IsUnspecified() && (ip.To4() == nil) != v6 {
			continue
		}
		for _, proto := range ruleProtocols(r) {
			scope := fmt.Sprintf("-p %s --dport %d", proto, p)
			if ip != nil && !ip.IsUnspecified() {
				scope += " -d " + ip.String()
			}
			for _, s := range c.Blacklist {
				if !familyMatch(s, v6) {
					continue
				}
				exceptions := false
				for _, w := range c.Whitelist {
					if familyMatch(w, v6) {
						exceptions = true
						break
					}
				}
				if exceptions {
					break
				}
				fmt.Fprintf(&b, "-A %s ! -i lo %s -s %s -j DROP\n", fwChain, scope, s)
			}
			// With a whitelist, filtering stays in the application to preserve CIDR exceptions exactly.
			if r.OpenFirewall {
				fmt.Fprintf(&b, "-A %s ! -i lo %s -j ACCEPT\n", fwChain, scope)
			}
		}
	}
	b.WriteString("-A " + fwChain + " -j RETURN\nCOMMIT\n")
	return b.String()
}
func (f *Firewall) sync(rules []Rule, c Config) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status := FWStatus{Enabled: f.enabled, State: "disabled", Message: "未授权防火墙管理", Ports: []string{}, Families: map[string]StatusPart{}, Checked: time.Now().Format(time.RFC3339)}
	defer func() { f.status = status; f.cache.Store(&status) }()
	if !f.enabled {
		return
	}
	for _, v6 := range []bool{false, true} {
		family := "ipv4"
		if v6 {
			family = "ipv6"
		}
		selected := []Rule{}
		for _, r := range rules {
			if r.ForwardMode != "kernel" {
				if _, ok := listenerAddress(r, v6); ok {
					selected = append(selected, r)
				}
			}
		}
		if len(selected) == 0 {
			status.Families[family] = StatusPart{State: "unused", Message: "无应用层规则"}
			if runtime.GOOS == "linux" {
				bin, _, _ := kernelTools(v6)
				f.run(bin, []string{"-w", "3", "-D", "INPUT", "-j", fwChain}, "")
				f.run(bin, []string{"-w", "3", "-F", fwChain}, "")
				f.run(bin, []string{"-w", "3", "-X", fwChain}, "")
			}
			continue
		}
		if err := f.syncInputFamily(selected, c, v6); err != nil {
			status.Families[family] = StatusPart{State: "error", Message: err.Error()}
			continue
		}
		status.Families[family] = StatusPart{State: "applied", Message: "规则已同步"}
		for _, r := range selected {
			if r.OpenFirewall {
				_, p, _ := hostPort(r.Listen)
				for _, proto := range ruleProtocols(r) {
					status.Ports = append(status.Ports, fmt.Sprintf("%s %d/%s", family, p, strings.ToUpper(proto)))
				}
			}
		}
	}
	status.State = "applied"
	status.Message = "所需地址族已分别同步；每 30 秒复核"
	for _, s := range status.Families {
		if s.State == "error" {
			status.State = "error"
			status.Message = "部分地址族同步失败，请查看各地址族结果"
		}
	}
	sort.Strings(status.Ports)
}
func (f *Firewall) syncInputFamily(rules []Rule, c Config, v6 bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("防火墙管理仅支持 Linux")
	}
	if b, e := f.readFile("/proc/self/status"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				n, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
				if n&(1<<12) == 0 || n&(1<<13) == 0 {
					return fmt.Errorf("缺少 NET_ADMIN / NET_RAW，未写入此地址族规则")
				}
			}
		}
	}
	bin, restore, _ := kernelTools(v6)
	if _, e := exec.LookPath(bin); e != nil {
		return fmt.Errorf("%s 不存在；未切换防火墙后端", bin)
	}
	if _, e := f.run(bin, []string{"-w", "3", "-S", fwChain}, ""); e != nil {
		if _, e = f.run(bin, []string{"-w", "3", "-N", fwChain}, ""); e != nil {
			return e
		}
	}
	batch := buildFirewall(rules, c, v6)
	if _, e := f.run(restore, []string{"-w", "3", "--noflush", "--test"}, batch); e != nil {
		return e
	}
	if _, e := f.run(restore, []string{"-w", "3", "--noflush"}, batch); e != nil {
		return e
	}
	if _, e := f.run(bin, []string{"-w", "3", "-C", "INPUT", "-j", fwChain}, ""); e != nil {
		_, e = f.run(bin, []string{"-w", "3", "-I", "INPUT", "1", "-j", fwChain}, "")
		return e
	}
	return nil
}
func (f *Firewall) cleanup() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.enabled {
		return
	}
	f.cleanupKernel()
	for _, bin := range []string{"iptables-legacy", "ip6tables-legacy"} {
		f.run(bin, []string{"-w", "3", "-D", "INPUT", "-j", fwChain}, "")
		f.run(bin, []string{"-w", "3", "-F", fwChain}, "")
		f.run(bin, []string{"-w", "3", "-X", fwChain}, "")
	}
}
