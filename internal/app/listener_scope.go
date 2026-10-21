package app

import "net"

// Describe the actual bind scope, including legacy/dual-stack wildcard binds.
// Explicit tcp6/udp6 listeners do not claim IPv4-mapped connections.
func listenerAddress(r Rule, v6 bool) (net.IP, bool) {
	h, _, err := hostPort(r.Listen)
	if err != nil || r.Network == "ipv4" && v6 || r.Network == "ipv6" && !v6 {
		return nil, false
	}
	if h == "" || h == "::" && (r.Network == "" || r.Network == "dual") {
		if v6 {
			return net.IPv6zero, true
		}
		return net.IPv4zero, true
	}
	ip := net.ParseIP(h)
	return ip, ip != nil && (ip.To4() == nil) == v6
}

func listenersOverlap(a, b Rule) bool {
	for _, v6 := range []bool{false, true} {
		x, xok := listenerAddress(a, v6)
		y, yok := listenerAddress(b, v6)
		if xok && yok && (x.IsUnspecified() || y.IsUnspecified() || x.Equal(y)) {
			return true
		}
	}
	return false
}
