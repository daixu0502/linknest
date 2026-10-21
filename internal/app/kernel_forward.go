package app

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
)

// Only application-owned chains are changed. IPv4 and IPv6 are applied and
// withdrawn independently; neither sysctls nor UCI/Docker chains are modified.
const kernelPre = "LNEST_DNAT"
const kernelPost = "LNEST_SNAT"
const kernelFilter = "LNEST_FWD"

func validateKernelRule(r Rule) error {
	h, _, err := hostPort(r.Listen)
	th, _, targetErr := hostPort(r.Target)
	ip, target := net.ParseIP(h), net.ParseIP(th)
	if (r.Kind != "tcp" && r.Kind != "udp" && r.Kind != "tcpudp") || err != nil || targetErr != nil || ip == nil || target == nil {
		return errors.New("内核加速需要 IP 地址:端口；域名目标请使用兼容转发，IPv6 地址需写为 [IPv6]:端口")
	}
	if r.Network != "ipv4" && r.Network != "ipv6" {
		return errors.New("内核加速请选择仅 IPv4 或仅 IPv6；双栈请分别创建同端口规则，或使用兼容转发")
	}
	if (ip.To4() == nil) != (r.Network == "ipv6") {
		return errors.New("内核监听 IP 与所选网络不一致")
	}
	if (ip.To4() == nil) != (target.To4() == nil) {
		return errors.New("IPv4 与 IPv6 互转请使用兼容转发；内核加速要求监听和目标属于同一地址族")
	}
	if ip.IsLoopback() || target.IsLoopback() || target.IsUnspecified() || target.IsMulticast() || target.Equal(net.IPv4bcast) || target.IsLinkLocalUnicast() && target.To4() == nil {
		return errors.New("内核目标需为可路由的非本机单播地址，不能使用回环、未指定、组播或 IPv6 链路本地地址")
	}
	return nil
}

func kernelRuleReady(r Rule) error {
	if err := validateKernelRule(r); err != nil {
		return err
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	h, _, _ := hostPort(r.Listen)
	th, _, _ := hostPort(r.Target)
	ip, target := net.ParseIP(h), net.ParseIP(th)
	local := map[string]bool{}
	for _, a := range addresses {
		if addr, _, err := net.ParseCIDR(a.String()); err == nil {
			local[addr.String()] = true
		}
	}
	if local[target.String()] || !ip.IsUnspecified() && !local[ip.String()] {
		return errors.New("目标不可为本机，监听 IP 必须属于本机网卡")
	}
	for _, proto := range ruleProtocols(r) {
		if proto == "tcp" {
			ln, err := net.Listen(listenNetwork(r, proto), r.Listen)
			if err != nil {
				return fmt.Errorf("本机 TCP 监听冲突（%s）：%w", r.Listen, err)
			}
			ln.Close()
		} else {
			ln, err := net.ListenPacket(listenNetwork(r, proto), r.Listen)
			if err != nil {
				return fmt.Errorf("本机 UDP 监听冲突（%s）：%w", r.Listen, err)
			}
			ln.Close()
		}
	}
	return nil
}

func kernelScope(r Rule, proto string) string {
	h, p, _ := hostPort(r.Listen)
	th, tp, _ := hostPort(r.Target)
	s := fmt.Sprintf("-p %s -d %s --dport %d -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport %d", proto, net.ParseIP(th).String(), tp, p)
	if ip := net.ParseIP(h); !ip.IsUnspecified() {
		s += " --ctorigdst " + ip.String()
	}
	return s
}

// ACCEPT is restricted to the translated tuple and original listening port.
// A whitelist bypasses this app's deny list, never the router's own policy.
func buildKernel(rules []Rule, c Config, v6 bool) (string, string) {
	var filter, nat strings.Builder
	filter.WriteString("*filter\n-F " + kernelFilter + "\n")
	nat.WriteString("*nat\n-F " + kernelPre + "\n-F " + kernelPost + "\n")
	for _, r := range rules {
		if !forwardFamily(r, v6) {
			continue
		}
		h, p, _ := hostPort(r.Listen)
		th, tp, _ := hostPort(r.Target)
		for _, proto := range ruleProtocols(r) {
			scope := kernelScope(r, proto)
			for _, ip := range c.Whitelist {
				if familyMatch(ip, v6) {
					fmt.Fprintf(&filter, "-A %s %s -s %s -j %s\n", kernelFilter, scope, ip, kernelVerdict(r))
				}
			}
			for _, ip := range c.Blacklist {
				if familyMatch(ip, v6) {
					fmt.Fprintf(&filter, "-A %s %s -s %s -j DROP\n", kernelFilter, scope, ip)
				}
			}
			fmt.Fprintf(&filter, "-A %s %s -j %s\n", kernelFilter, scope, kernelVerdict(r))
			listen := fmt.Sprintf("! -i lo -p %s --dport %d -m addrtype --dst-type LOCAL", proto, p)
			if ip := net.ParseIP(h); !ip.IsUnspecified() {
				listen += " -d " + ip.String()
			}
			fmt.Fprintf(&nat, "-A %s %s -j DNAT --to-destination %s\n", kernelPre, listen, net.JoinHostPort(net.ParseIP(th).String(), strconv.Itoa(tp)))
			// Source NAT remains the default for existing rules. Preserving source IP
			// requires the backend's return route to use this router, also for hairpin.
			if !r.PreserveClientIP {
				fmt.Fprintf(&nat, "-A %s %s -j MASQUERADE\n", kernelPost, scope)
			}
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

func kernelTools(v6 bool) (string, string, string) {
	if v6 {
		return "ip6tables-legacy", "ip6tables-legacy-restore", "IPv6"
	}
	return "iptables-legacy", "iptables-legacy-restore", "IPv4"
}

func (f *Firewall) cleanupKernelFamily(v6 bool) {
	bin, _, _ := kernelTools(v6)
	for _, v := range kernelChains {
		f.run(bin, []string{"-w", "3", "-t", v.table, "-D", v.parent, "-j", v.chain}, "")
		f.run(bin, []string{"-w", "3", "-t", v.table, "-F", v.chain}, "")
		f.run(bin, []string{"-w", "3", "-t", v.table, "-X", v.chain}, "")
	}
}
func (f *Firewall) cleanupKernel() { f.cleanupKernelFamily(false); f.cleanupKernelFamily(true) }

// A missing IPv6 NAT module must not withdraw successful IPv4 rules.
func (f *Firewall) syncKernelByRule(active []Rule, c Config) map[string]error {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]error{}
	for _, v6 := range []bool{false, true} {
		rules := []Rule{}
		for _, r := range active {
			if r.ForwardMode == "kernel" && forwardFamily(r, v6) {
				rules = append(rules, r)
			}
		}
		var err error
		if !f.enabled {
			err = errors.New("需要授权防火墙管理及 host 网络")
		} else if runtime.GOOS != "linux" {
			err = errors.New("仅支持 Linux host 网络")
		} else {
			err = f.syncKernelFamily(rules, c, v6)
		}
		if err != nil {
			for _, r := range rules {
				out[r.ID] = err
			}
		}
	}
	return out
}
func (f *Firewall) syncKernel(active []Rule, c Config) error {
	errs := []error{}
	for _, err := range f.syncKernelByRule(active, c) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Called with f.mu held. Withdraw only this family's chains on failure.
func (f *Firewall) syncKernelFamily(rules []Rule, c Config, v6 bool) (result error) {
	bin, restore, family := kernelTools(v6)
	defer func() {
		if result != nil {
			f.cleanupKernelFamily(v6)
		}
	}()
	if len(rules) == 0 {
		for _, chain := range kernelChains {
			if _, err := f.run(bin, []string{"-w", "3", "-t", chain.table, "-S", chain.chain}, ""); err == nil {
				f.cleanupKernelFamily(v6)
				break
			}
		}
		return nil
	}
	path := "/proc/sys/net/ipv4/ip_forward"
	if v6 {
		path = "/proc/sys/net/ipv6/conf/all/forwarding"
	}
	if data, err := f.readFile(path); err != nil || strings.TrimSpace(string(data)) != "1" {
		return fmt.Errorf("路由器 %s 转发未开启或无法读取；未修改系统开关，请检查后重试或使用兼容转发", family)
	}
	for _, r := range rules {
		if err := kernelRuleReady(r); err != nil {
			return err
		}
	}
	if _, err := f.run(bin, []string{"-w", "3", "-t", "nat", "-S"}, ""); err != nil {
		return fmt.Errorf("%s NAT 不可用，请检查内核模块和权限或改用兼容转发：%w", family, err)
	}
	for _, v := range kernelChains {
		if _, err := f.run(bin, []string{"-w", "3", "-t", v.table, "-S", v.chain}, ""); err != nil {
			if _, err := f.run(bin, []string{"-w", "3", "-t", v.table, "-N", v.chain}, ""); err != nil {
				return err
			}
		}
	}
	filter, nat := buildKernel(rules, c, v6)
	// Check both batches before publication; install FORWARD policy before DNAT.
	for _, batch := range []string{filter, nat} {
		if _, err := f.run(restore, []string{"-w", "3", "--noflush", "--test"}, batch); err != nil {
			return err
		}
	}
	if _, err := f.run(restore, []string{"-w", "3", "--noflush"}, filter); err != nil {
		return err
	}
	if err := f.hookKernel(bin, "filter", "FORWARD", kernelFilter); err != nil {
		return err
	}
	if _, err := f.run(restore, []string{"-w", "3", "--noflush"}, nat); err != nil {
		return err
	}
	for _, v := range kernelChains[:2] {
		if err := f.hookKernel(bin, v.table, v.parent, v.chain); err != nil {
			return err
		}
	}
	return nil
}
func (f *Firewall) hookKernel(bin, table, parent, chain string) error {
	if _, err := f.run(bin, []string{"-w", "3", "-t", table, "-C", parent, "-j", chain}, ""); err != nil {
		_, err = f.run(bin, []string{"-w", "3", "-t", table, "-I", parent, "1", "-j", chain}, "")
		return err
	}
	return nil
}
