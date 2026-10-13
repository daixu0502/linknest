package app

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

type webSnapshot struct {
	rules  []Rule
	routes []WebRoute
	owners map[string]Rule
}
type webRunning struct {
	ref  *atomic.Pointer[webSnapshot]
	stop func()
}

func webListenKey(r Rule) string {
	h, p, _ := hostPort(r.Listen)
	network := listenNetwork(r, "tcp")
	if h == "" {
		if network == "tcp4" {
			h = "0.0.0.0"
		} else {
			h = "::"
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		h = ip.String()
	}
	return network + "|" + net.JoinHostPort(h, strconv.Itoa(p))
}

func routeDomainKey(d string) string {
	d = strings.ToLower(strings.TrimSuffix(strings.Trim(d, "[]"), "."))
	if ip := net.ParseIP(d); ip != nil {
		return ip.String()
	}
	return d
}

func validateSharedWebRules(rules []Rule) error {
	seen := map[string]map[string]string{}
	for _, r := range rules {
		if !r.Enabled || r.Kind != "web" {
			continue
		}
		key := webListenKey(r)
		if seen[key] == nil {
			seen[key] = map[string]string{}
		}
		for _, route := range r.Routes {
			if !route.Enabled {
				continue
			}
			domains := route.Domains
			if len(domains) == 0 {
				domains = []string{"*"}
			}
			for _, domain := range domains {
				domain = routeDomainKey(domain)
				if owner, ok := seen[key][domain]; ok {
					return fmt.Errorf("同端口域名 %s 重复：%s 与 %s / %s；默认入口也只能有一个", domain, owner, r.Name, route.Name)
				}
				seen[key][domain] = r.Name + " / " + route.Name
			}
		}
	}
	return nil
}

func newWebSnapshot(rules []Rule) *webSnapshot {
	s := &webSnapshot{rules: append([]Rule{}, rules...), owners: map[string]Rule{}}
	for _, r := range rules {
		for _, route := range r.Routes {
			route.Domains = append([]string{}, route.Domains...)
			s.routes = append(s.routes, route)
			s.owners[route.ID] = r
		}
	}
	return s
}

func (s *webSnapshot) match(host string) (*WebRoute, Rule) {
	route := matchRoute(s.routes, host)
	if route == nil {
		return nil, Rule{}
	}
	return route, s.owners[route.ID]
}

// A firewall allows ports, not HTTP domains. One enabled owner's request opens
// the shared port; fold identical listeners rather than writing duplicate rules.
func sharedFirewallRules(rules []Rule) []Rule {
	out := []Rule{}
	seen := map[string]int{}
	for _, r := range rules {
		if r.Kind != "web" {
			out = append(out, r)
			continue
		}
		key := webListenKey(r)
		if i, ok := seen[key]; ok {
			out[i].OpenFirewall = out[i].OpenFirewall || r.OpenFirewall
			continue
		}
		seen[key] = len(out)
		out = append(out, r)
	}
	return out
}
