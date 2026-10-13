package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

type InterfaceAddress struct {
	Name string   `json:"name"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

func publicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		_, n, _ := net.ParseCIDR(s)
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
func interfaces() []InterfaceAddress {
	out := []InterfaceAddress{}
	ifs, _ := net.Interfaces()
	for _, it := range ifs {
		if it.Flags&net.FlagUp == 0 || it.Flags&net.FlagLoopback != 0 {
			continue
		}
		a := InterfaceAddress{Name: it.Name, IPv4: []string{}, IPv6: []string{}}
		addrs, _ := it.Addrs()
		for _, s := range addrs {
			ip, _, e := net.ParseCIDR(s.String())
			if e != nil || !publicIP(ip) {
				continue
			}
			if ip.To4() != nil {
				a.IPv4 = append(a.IPv4, ip.String())
			} else {
				a.IPv6 = append(a.IPv6, ip.String())
			}
		}
		sort.Strings(a.IPv4)
		sort.Strings(a.IPv6)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func pickInterface(items []InterfaceAddress, name string, v6 bool) (string, error) {
	candidates := []string{}
	for _, it := range items {
		if name != "" && it.Name != name {
			continue
		}
		if name == "" && (strings.HasPrefix(it.Name, "veth") || strings.HasPrefix(it.Name, "docker") || strings.HasPrefix(it.Name, "br-") || strings.HasPrefix(it.Name, "tun")) {
			continue
		}
		if v6 {
			candidates = append(candidates, it.IPv6...)
		} else {
			candidates = append(candidates, it.IPv4...)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) > 1 {
		return "", errors.New("存在多个公网地址，请使用出口检测接口或选择明确网卡")
	}
	return "", errors.New("未发现对应公网地址；请检查 IPv6 接入及 host 网络模式")
}
func detectURL(ctx context.Context, address string, v6 bool) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return "", errors.New("检测地址无效")
	}
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, network, addr)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 || req.URL.Scheme != "https" {
			return errors.New("拒绝非 HTTPS 重定向")
		}
		return nil
	}}
	res, err := client.Do(req)
	if err != nil {
		return "", errors.New("公网 IP 接口连接失败（请检查该协议族出网）")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 128))
	if err != nil || res.StatusCode != 200 {
		return "", errors.New("IP 检测接口返回异常")
	}
	ip := net.ParseIP(strings.TrimSpace(string(b)))
	if !publicIP(ip) || (ip.To4() == nil) != v6 {
		return "", errors.New("接口未返回所需协议族的公网 IP")
	}
	return ip.String(), nil
}
func detectIP(ctx context.Context, s IPSource, v6 bool) (string, error) {
	if s.Mode == "interface" {
		return pickInterface(interfaces(), s.Interface, v6)
	}
	if s.Mode == "url" {
		return detectURL(ctx, s.URL, v6)
	}
	if v6 {
		if v, err := pickInterface(interfaces(), "", true); err == nil {
			return v, nil
		}
	}
	endpoint := "https://api4.ipify.org"
	if v6 {
		endpoint = "https://api6.ipify.org"
	}
	return detectURL(ctx, endpoint, v6)
}
