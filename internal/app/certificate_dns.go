package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type txtTarget struct {
	Label, Address string
	Authority      bool
}

func dnsResolver(address string, tcp bool) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		// Honor Go's TCP fallback for truncated UDP responses.
		if tcp {
			network = "tcp"
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}}
}
func txtTargets(ctx context.Context, zone string) []txtTarget {
	out := []txtTarget{}
	resolver := dnsResolver("223.5.5.5:53", false)
	q, stop := context.WithTimeout(ctx, 8*time.Second)
	defer stop()
	ns, err := resolver.LookupNS(q, zone)
	if err != nil {
		ns, _ = dnsResolver("223.6.6.6:53", true).LookupNS(q, zone)
	}
	for _, n := range ns {
		ips, e := resolver.LookupIP(q, "ip4", n.Host)
		if e == nil && len(ips) > 0 {
			out = append(out, txtTarget{Label: strings.TrimSuffix(n.Host, "."), Address: net.JoinHostPort(ips[0].String(), "53"), Authority: true})
		}
		if len(out) >= 2 {
			break
		}
	}
	out = append(out, txtTarget{Label: "递归 DNS 223.5.5.5", Address: "223.5.5.5:53"})
	if len(out) == 1 {
		out = append(out, txtTarget{Label: "递归 DNS 223.6.6.6", Address: "223.6.6.6:53"})
	}
	return out
}
func lookupExpectedTXT(ctx context.Context, t txtTarget, name, value string) (bool, string) {
	var txt []string
	var err error
	for _, tcp := range []bool{false, true} {
		q, stop := context.WithTimeout(ctx, 3*time.Second)
		txt, err = dnsResolver(t.Address, tcp).LookupTXT(q, name)
		stop()
		if err == nil {
			break
		}
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return false, "尚无 TXT 记录（可能缓存了旧结果）"
		}
	}
	if err != nil {
		return false, "DNS 查询失败 / 超时（UDP 与 TCP 均未成功）"
	}
	for _, s := range txt {
		if s == value {
			return true, "已查到本次验证 TXT"
		}
	}
	return false, fmt.Sprintf("已返回 %d 条 TXT，但不含本次验证值", len(txt))
}
func waitExpectedTXT(ctx context.Context, targets []txtTarget, name, value string, query func(context.Context, txtTarget, string, string) (bool, string), note func(string), interval time.Duration) error {
	last := ""
	for {
		type result struct {
			ok      bool
			message string
		}
		results := make([]result, len(targets))
		var wg sync.WaitGroup
		for i, t := range targets {
			wg.Add(1)
			go func(i int, t txtTarget) {
				defer wg.Done()
				results[i].ok, results[i].message = query(ctx, t, name, value)
			}(i, t)
		}
		wg.Wait()
		authN, authOK, recursiveOK := 0, 0, 0
		details := []string{}
		for i, t := range targets {
			if t.Authority {
				authN++
				if results[i].ok {
					authOK++
				}
			} else if results[i].ok {
				recursiveOK++
			}
			details = append(details, t.Label+"："+results[i].message)
		}
		text := strings.Join(details, "；")
		if text != last {
			note(text)
			last = text
		}
		if (authN > 0 && authOK == authN) || (authN == 0 && recursiveOK == len(targets) && len(targets) > 0) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("DNS TXT 传播检测未完成：%s；请核对权威 NS、DNS 查询链路和是否存在 CNAME 委派。原证书未替换", last)
		case <-time.After(interval):
		}
	}
}
func (c *CertManager) waitDNS(ctx context.Context, id, zone, name, value string) error {
	c.progress(id, "dns_wait", "等待 TXT 生效："+name+"；先检查权威 DNS，最长 6 分钟")
	q, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	targets := txtTargets(q, zone)
	return waitExpectedTXT(q, targets, name, value, lookupExpectedTXT, func(message string) { c.progress(id, "dns_wait", name+" · "+message) }, 5*time.Second)
}
