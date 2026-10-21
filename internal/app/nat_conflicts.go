package app

import (
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
)

// Read once per apply, not once per port. DNAT/UPnP does not own a listening
// socket, so a successful bind alone cannot establish that forwarding works.
// Only inspect router rules; never remove or reorder another service's rules.
func (f *Firewall) forwardConflicts(rules []Rule) map[string]error {
	out := map[string]error{}
	if !f.enabled || runtime.GOOS != "linux" {
		return out
	}
	for _, v6 := range []bool{false, true} {
		family := []Rule{}
		for _, r := range rules {
			if r.Enabled && r.Kind != "web" && forwardFamily(r, v6) {
				family = append(family, r)
			}
		}
		if len(family) == 0 {
			continue
		}
		bin := "iptables-legacy"
		if v6 {
			bin = "ip6tables-legacy"
		}
		data, err := f.run(bin, []string{"-w", "3", "-t", "nat", "-S"}, "")
		if err != nil {
			// Older IPv6 kernels may not implement NAT at all. Permission and
			// command errors are NOT an empty snapshot or a successful check.
			if v6 && strings.Contains(data, "Table does not exist") {
				continue
			}
			for _, r := range family {
				out[r.ID] = fmt.Errorf("无法核对路由器 NAT 映射（%s）；未启动此转发：%w", bin, err)
			}
			continue
		}
		for id, err := range natConflicts(data, family, v6) {
			out[id] = err
		}
	}
	return out
}

func forwardFamily(r Rule, v6 bool) bool {
	_, ok := listenerAddress(r, v6)
	return ok
}

// iptables -S quotes comments. Parse those quotes so words inside a comment
// (even '-j DNAT') can never be mistaken for an actual jump or port option.
func natWords(line string) []string {
	var out []string
	var b strings.Builder
	quote, escape, started := rune(0), false, false
	for _, c := range line {
		if escape {
			b.WriteRune(c)
			escape = false
		} else if c == '\\' {
			escape, started = true, true
		} else if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				b.WriteRune(c)
			}
		} else if c == '\'' || c == '"' {
			quote, started = c, true
		} else if c == ' ' || c == '\t' || c == '\r' {
			if started {
				out = append(out, b.String())
				b.Reset()
				started = false
			}
		} else {
			b.WriteRune(c)
			started = true
		}
	}
	if started {
		out = append(out, b.String())
	}
	return out
}

type natEntry struct {
	words        []string
	jump, target string
}
type natPath struct {
	entries []natEntry
	chain   string
}

func natConflicts(snapshot string, rules []Rule, v6 bool) map[string]error {
	chains := map[string][]natEntry{}
	for _, line := range strings.Split(snapshot, "\n") {
		w := natWords(line)
		if len(w) < 4 || w[0] != "-A" {
			continue
		}
		e := natEntry{words: w[2:]}
		for i := 2; i+1 < len(w); i++ {
			switch w[i] {
			case "--comment":
				i++
			case "-j", "--jump", "-g", "--goto":
				e.jump = w[i+1]
				i++
			case "--to-destination", "--to-ports":
				e.target = w[i+1]
				i++
			}
		}
		chains[w[1]] = append(chains[w[1]], e)
	}
	// Only mappings reachable from ingress can steal incoming connections.
	// Ignore our own chain, unattached old chains and OUTPUT-only redirects.
	paths := []natPath{}
	visited, exhausted := 0, false
	var walk func(string, []natEntry, map[string]bool)
	walk = func(chain string, prefix []natEntry, seen map[string]bool) {
		if exhausted || seen[chain] || chain == kernelPre {
			return
		}
		if len(prefix) > 32 {
			exhausted = true
			return
		}
		seen[chain] = true
		defer delete(seen, chain)
		for _, e := range chains[chain] {
			visited++
			if visited > 16384 {
				exhausted = true
				return
			}
			path := append(append([]natEntry(nil), prefix...), e)
			if e.jump == "DNAT" || e.jump == "REDIRECT" {
				paths = append(paths, natPath{path, chain})
			} else if _, ok := chains[e.jump]; ok {
				walk(e.jump, path, seen)
			}
		}
	}
	walk("PREROUTING", nil, map[string]bool{})
	out := map[string]error{}
	if exhausted {
		for _, r := range rules {
			out[r.ID] = fmt.Errorf("路由器 NAT 规则路径过多，无法安全完成冲突检测；未启动此转发")
		}
		return out
	}
	for _, r := range rules {
		h, port, err := hostPort(r.Listen)
		if err != nil || !forwardFamily(r, v6) {
			continue
		}
		for _, proto := range ruleProtocols(r) {
			for _, path := range paths {
				if !natPathMatches(path.entries, h, port, proto, v6) {
					continue
				}
				source := "路由器 NAT"
				for _, e := range path.entries {
					if strings.Contains(strings.ToUpper(e.jump), "UPNP") {
						source = "UPnP / PCP"
					}
				}
				family := "IPv4"
				if v6 {
					family = "IPv6"
				}
				out[r.ID] = fmt.Errorf("%s %s/%d 与%s映射冲突（%s → %s）；请更换端口或自行调整已有映射", family, strings.ToUpper(proto), port, source, path.chain, path.entries[len(path.entries)-1].target)
				break
			}
			if out[r.ID] != nil {
				break
			}
		}
	}
	return out
}

func natPathMatches(path []natEntry, host string, port int, proto string, v6 bool) bool {
	bits := 32
	if v6 {
		bits = 128
	}
	base := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if v6 {
		base = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	if ip, err := netip.ParseAddr(host); err == nil && !ip.IsUnspecified() {
		base = netip.PrefixFrom(ip.Unmap(), bits)
	}
	excluded := []netip.Prefix{}
	for _, e := range path {
		neg := false
		for i := 0; i < len(e.words); i++ {
			key := e.words[i]
			if key == "!" {
				neg = true
				continue
			}
			if i+1 >= len(e.words) {
				break
			}
			value := e.words[i+1]
			// -S emits '! --option value', not '--option ! value'.
			match, checked := true, false
			switch key {
			case "--comment":
				i++
			case "-p", "--protocol":
				checked = true
				match = value == proto || value == "all" || value == "0" || value == "6" && proto == "tcp" || value == "17" && proto == "udp"
				i++
			case "--dport", "--destination-port", "--dports", "--destination-ports":
				checked = true
				match = natPortMatches(value, port)
				i++
			case "-i", "--in-interface":
				// Loopback-only paths cannot affect external/LAN clients.
				if value == "lo" && !neg {
					return false
				}
				i++
			case "-d", "--destination":
				p, err := netip.ParsePrefix(value)
				if err != nil {
					if a, er := netip.ParseAddr(value); er == nil {
						p = netip.PrefixFrom(a, a.BitLen())
					} else {
						i++
						break
					}
				}
				p = p.Masked()
				i++
				if p.Addr().Is4() == v6 {
					return false
				}
				if neg {
					excluded = append(excluded, p)
				} else {
					if !base.Overlaps(p) {
						return false
					}
					if p.Bits() > base.Bits() {
						base = p
					}
				}
			}
			if checked && match == neg {
				return false
			}
			neg = false
		}
	}
	for _, p := range excluded {
		if p.Bits() <= base.Bits() && p.Contains(base.Addr()) {
			return false
		}
	}
	return true
}

func natPortMatches(value string, port int) bool {
	for _, v := range strings.Split(value, ",") {
		parts := strings.SplitN(v, ":", 2)
		low, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		high := low
		if len(parts) == 2 {
			high, err = strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
		}
		if port >= low && port <= high {
			return true
		}
	}
	return false
}
