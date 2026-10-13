package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// No UCI/Docker chains or sysctls are modified. IPv6/domain destinations stay
// on the userspace path; no silent fallback to a weaker filtering policy.
const kernelPre = "LNEST_DNAT"
const kernelPost = "LNEST_SNAT"
const kernelFilter = "LNEST_FWD"

func validateKernelRule(r Rule) error {
	h, _, err := hostPort(r.Listen)
	th, _, targetErr := hostPort(r.Target)
	ip, target := net.ParseIP(h), net.ParseIP(th)
	if r.Kind == "web" || r.Network != "ipv4" || err != nil || targetErr != nil ||
		ip == nil || ip.To4() == nil || target == nil || target.To4() == nil ||
		ip.IsLoopback() || target.IsLoopback() || target.IsUnspecified() || target.IsMulticast() || target.Equal(net.IPv4bcast) {
		return errors.New("内核加速仅支持 IPv4 TCP/UDP，监听 IPv4 本机地址，目标需为非本机的 IPv4 地址:端口；域名和 IPv6 请使用兼容转发")
	}
	return nil
}

func kernelScope(r Rule, proto string) string {
	h, p, _ := hostPort(r.Listen)
	th, tp, _ := hostPort(r.Target)
	s := fmt.Sprintf("-p %s -d %s --dport %d -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport %d", proto, th, tp, p)
	if h != "0.0.0.0" {
		s += " --ctorigdst " + h
	}
	return s
}

// ACCEPT, when requested, is restricted to the translated target, port,
// protocol AND original port. Whitelist bypasses our deny list, not fw3.
func buildKernel(rules []Rule, c Config) (string, string) {
	var filter, nat strings.Builder
	filter.WriteString("*filter\n-F " + kernelFilter + "\n")
	nat.WriteString("*nat\n-F " + kernelPre + "\n-F " + kernelPost + "\n")
	for _, r := range rules {
		h, p, _ := hostPort(r.Listen)
		for _, proto := range ruleProtocols(r) {
			scope := kernelScope(r, proto)
			for _, ip := range c.Whitelist {
				if familyMatch(ip, false) {
					fmt.Fprintf(&filter, "-A %s %s -s %s -j %s\n", kernelFilter, scope, ip, kernelVerdict(r))
				}
			}
			for _, ip := range c.Blacklist {
				if familyMatch(ip, false) {
					fmt.Fprintf(&filter, "-A %s %s -s %s -j DROP\n", kernelFilter, scope, ip)
				}
			}
			fmt.Fprintf(&filter, "-A %s %s -j %s\n", kernelFilter, scope, kernelVerdict(r))
			listen := fmt.Sprintf("! -i lo -p %s --dport %d -m addrtype --dst-type LOCAL", proto, p)
			if h != "0.0.0.0" {
				listen += " -d " + h
			}
			fmt.Fprintf(&nat, "-A %s %s -j DNAT --to-destination %s\n", kernelPre, listen, r.Target)
			// Match only our translated tuples, including LAN hairpin. Preserve
			// current proxy semantics: the target sees the router's address.
			fmt.Fprintf(&nat, "-A %s %s -j MASQUERADE\n", kernelPost, scope)
		}
	}
	filter.WriteString("-A " + kernelFilter + " -j RETURN\nCOMMIT\n")
	nat.WriteString("-A " + kernelPre + " -j RETURN\n-A " + kernelPost + " -j RETURN\nCOMMIT\n")
	return filter.String(), nat.String()
}
func kernelVerdict(r Rule) string {
	if r.OpenFirewall {
		return "ACCEPT"
	}
	return "RETURN"
}

var kernelChains = []struct{ table, chain, parent string }{
	{"nat", kernelPre, "PREROUTING"}, {"nat", kernelPost, "POSTROUTING"}, {"filter", kernelFilter, "FORWARD"},
}

func (f *Firewall) cleanupKernel() {
	for _, v := range kernelChains {
		f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-D", v.parent, "-j", v.chain}, "")
		f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-F", v.chain}, "")
		f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-X", v.chain}, "")
	}
}
func (f *Firewall) syncKernel(active []Rule, c Config) (result error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rules := []Rule{}
	for _, r := range active {
		if r.ForwardMode == "kernel" {
			rules = append(rules, r)
		}
	}
	if !f.enabled {
		if len(rules) > 0 {
			return errors.New("需要授权防火墙管理及 host 网络")
		}
		return nil
	}
	if runtime.GOOS != "linux" {
		if len(rules) > 0 {
			return errors.New("仅支持 Linux host 网络")
		}
		return nil
	}
	// On validation/apply error withdraw DNAT first; never report success or
	// silently relay without filters. Does not flush unrelated rules.
	defer func() {
		if result != nil {
			f.cleanupKernel()
		}
	}()
	if len(rules) == 0 {
		// Avoid 9 subprocesses on every tick when kernel mode was never used.
		for _, chain := range kernelChains {
			if _, err := f.run("iptables-legacy", []string{"-w", "3", "-t", chain.table, "-S", chain.chain}, ""); err == nil {
				f.cleanupKernel()
				break
			}
		}
		return nil
	}
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil || strings.TrimSpace(string(data)) != "1" {
		return errors.New("路由器 IPv4 转发未开启；未修改系统开关")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	local := map[string]bool{}
	for _, a := range addresses {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip != nil {
			local[ip.String()] = true
		}
	}
	for _, r := range rules {
		if err := validateKernelRule(r); err != nil {
			return err
		}
		h, _, _ := hostPort(r.Listen)
		th, _, _ := hostPort(r.Target)
		if local[th] || h != "0.0.0.0" && !local[h] {
			return errors.New("目标不可为本机，监听 IP 必须属于本机网卡")
		}
		// Refuse to intercept ports already owned by another local service.
		for _, proto := range ruleProtocols(r) {
			if proto == "tcp" {
				ln, err := net.Listen("tcp4", r.Listen)
				if err != nil {
					return fmt.Errorf("端口已占用：%w", err)
				}
				ln.Close()
			} else {
				ln, err := net.ListenPacket("udp4", r.Listen)
				if err != nil {
					return fmt.Errorf("端口已占用：%w", err)
				}
				ln.Close()
			}
		}
	}
	for _, v := range kernelChains {
		if _, err := f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-S", v.chain}, ""); err != nil {
			if _, err := f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-N", v.chain}, ""); err != nil {
				return err
			}
		}
	}
	filter, nat := buildKernel(rules, c)
	// A valid scoped filter is installed BEFORE any new DNAT is exposed.
	if _, err := f.run("iptables-legacy-restore", []string{"-w", "3", "--noflush"}, filter); err != nil {
		return err
	}
	// Install filter hook before publishing NAT; parent chains remain intact.
	for _, v := range []struct{ table, chain, parent string }{{"filter", kernelFilter, "FORWARD"}} {
		if _, err := f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-C", v.parent, "-j", v.chain}, ""); err != nil {
			if _, err := f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-I", v.parent, "1", "-j", v.chain}, ""); err != nil {
				return err
			}
		}
	}
	if _, err := f.run("iptables-legacy-restore", []string{"-w", "3", "--noflush"}, nat); err != nil {
		return err
	}
	for _, v := range kernelChains[:2] {
		if _, err := f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-C", v.parent, "-j", v.chain}, ""); err != nil {
			if _, err := f.run("iptables-legacy", []string{"-w", "3", "-t", v.table, "-I", v.parent, "1", "-j", v.chain}, ""); err != nil {
				return err
			}
		}
	}
	return nil
}
