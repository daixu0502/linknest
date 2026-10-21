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
	"time"
)

// Only these application-owned chains are ever flushed. Never flush INPUT, UCI, or Docker chains.
const fwChain = "LNEST_IN"

type FWStatus struct {
	Enabled bool     `json:"enabled"`
	State   string   `json:"state"`
	Message string   `json:"message"`
	Ports   []string `json:"ports"`
}
type Firewall struct {
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
func (f *Firewall) get() FWStatus { f.mu.Lock(); defer f.mu.Unlock(); return f.status }
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
	if !f.enabled {
		return
	}
	f.status.Enabled = true
	f.status.Ports = []string{}
	if runtime.GOOS != "linux" {
		f.status.State = "error"
		f.status.Message = "防火墙管理仅支持 Linux"
		return
	}
	if b, e := os.ReadFile("/proc/self/status"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				n, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
				if n&(1<<12) == 0 {
					f.status.State = "error"
					f.status.Message = "缺少 NET_ADMIN；没有写入任何防火墙规则"
					return
				}
				if n&(1<<13) == 0 {
					f.status.State = "error"
					f.status.Message = "legacy iptables 还需 NET_RAW；没有写入任何防火墙规则"
					return
				}
			}
		}
	}
	for _, v6 := range []bool{false, true} {
		bin, restore := "iptables-legacy", "iptables-legacy-restore"
		if v6 {
			bin, restore = "ip6tables-legacy", "ip6tables-legacy-restore"
		}
		if _, e := exec.LookPath(bin); e != nil {
			f.status.State = "error"
			f.status.Message = bin + " 不存在，拒绝切换到未知防火墙后端"
			return
		}
		if _, e := f.run(bin, []string{"-w", "3", "-S", fwChain}, ""); e != nil {
			if _, e = f.run(bin, []string{"-w", "3", "-N", fwChain}, ""); e != nil {
				f.status.State = "error"
				f.status.Message = e.Error()
				return
			}
		}
		if _, e := f.run(restore, []string{"-w", "3", "--noflush"}, buildFirewall(rules, c, v6)); e != nil {
			f.status.State = "error"
			f.status.Message = e.Error()
			return
		}
		if _, e := f.run(bin, []string{"-w", "3", "-C", "INPUT", "-j", fwChain}, ""); e != nil {
			if _, e = f.run(bin, []string{"-w", "3", "-I", "INPUT", "1", "-j", fwChain}, ""); e != nil {
				f.status.State = "error"
				f.status.Message = e.Error()
				return
			}
		}
	}
	for _, r := range rules {
		if r.OpenFirewall {
			_, p, _ := hostPort(r.Listen)
			for _, proto := range ruleProtocols(r) {
				f.status.Ports = append(f.status.Ports, fmt.Sprintf("%d/%s", p, strings.ToUpper(proto)))
			}
		}
	}
	sort.Strings(f.status.Ports)
	f.status.State = "applied"
	f.status.Message = "已同步自身 IPv4/IPv6 规则；每 30 秒复核"
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
