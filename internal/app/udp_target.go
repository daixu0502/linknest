package app

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

type udpTarget struct {
	address *net.UDPAddr
	err     error
	expires time.Time
	raw     string
	resolve func(context.Context, string) ([]net.IPAddr, error)
}

func (t *udpTarget) get(ctx context.Context) (*net.UDPAddr, error) {
	if time.Now().Before(t.expires) {
		return t.address, t.err
	}
	host, port, err := net.SplitHostPort(t.raw)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil || strings.Contains(host, "%") {
		t.address, t.err = net.ResolveUDPAddr("udp", t.raw)
		t.expires = time.Now().Add(time.Hour)
		return t.address, t.err
	}
	resolve := t.resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupIPAddr
	}
	lookup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := resolve(lookup, host)
	t.address = nil
	t.err = err
	t.expires = time.Now().Add(5 * time.Second)
	if err == nil && len(ips) > 0 {
		selected := ips[0]
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				selected = ip
				break
			}
		}
		n, _ := strconv.Atoi(port)
		t.address = &net.UDPAddr{IP: selected.IP, Zone: selected.Zone, Port: n}
		t.expires = time.Now().Add(time.Minute)
	} else if err == nil {
		t.err = &net.DNSError{Name: host, Err: "没有可用地址"}
	}
	return t.address, t.err
}
