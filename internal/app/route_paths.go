package app

import (
	"errors"
	"net"
	"path"
	"strings"
)

func canonicalPrefix(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return strings.TrimSuffix(p, "/")
}
func validatePathPrefix(p string) error {
	p = canonicalPrefix(p)
	if len(p) > 1024 || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\\%\r\n\t") || path.Clean(p) != p {
		return errors.New("路径前缀需以 / 开头，不能包含查询串、编码分隔符或 . / .. 路径段")
	}
	return nil
}
func pathMatches(prefix, requestPath string) bool {
	prefix = canonicalPrefix(prefix)
	return prefix == "/" || requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/")
}
func domainScore(domain, host string) int {
	domain = routeDomainKey(domain)
	if domain == "*" {
		return 0
	}
	if domain == host {
		return 10000 + len(domain)
	}
	if strings.HasPrefix(domain, "*.") && strings.HasSuffix(host, domain[1:]) && len(host) > len(domain)-1 {
		return len(domain)
	}
	return -1
}

// Domain ownership is resolved first. A path miss never falls through to a
// less specific domain or another owner's wildcard/default service.
func matchRoutePath(routes []WebRoute, host, requestPath string) (*WebRoute, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = routeDomainKey(host)
	domainBest, pathBest := -1, -1
	var best *WebRoute
	for i := range routes {
		r := &routes[i]
		if !r.Enabled {
			continue
		}
		domains := r.Domains
		if len(domains) == 0 {
			domains = []string{"*"}
		}
		for _, d := range domains {
			score := domainScore(d, host)
			if score < 0 || score < domainBest {
				continue
			}
			if score > domainBest {
				domainBest = score
				pathBest = -1
				best = nil
			}
			prefix := canonicalPrefix(r.PathPrefix)
			if pathMatches(prefix, requestPath) && len(prefix) > pathBest {
				best = r
				pathBest = len(prefix)
			}
		}
	}
	return best, domainBest >= 0
}
