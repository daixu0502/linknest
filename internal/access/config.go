// Package access implements bounded, application-scoped abuse prevention and
// independently cached IP feeds. It never trusts client-supplied forwarding headers.
package access

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const MaxEntries = 50000
const MaxSources = 16
const MaxBans = 5000
const MaxCounters = 10000
const MaxBody = 8 << 20

type AutoBan struct {
	Enabled       bool     `json:"enabled"`
	Threshold     int      `json:"threshold"`
	WindowSeconds int      `json:"windowSeconds"`
	BanSeconds    int      `json:"banSeconds"`
	StatusCodes   []int    `json:"statusCodes"`
	IgnorePrivate bool     `json:"ignorePrivate"`
	IgnoredPaths  []string `json:"ignoredPaths"`
}
type Source struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	Format        string `json:"format"`
	Enabled       bool   `json:"enabled"`
	IntervalHours int    `json:"intervalHours"`
}
type Config struct {
	Version int      `json:"version"`
	AutoBan AutoBan  `json:"autoBan"`
	Sources []Source `json:"sources"`
}

func DefaultConfig() Config {
	return Config{Version: 1, AutoBan: AutoBan{Threshold: 20, WindowSeconds: 60, BanSeconds: 3600, StatusCodes: []int{404}, IgnorePrivate: true, IgnoredPaths: []string{"/favicon.ico", "/robots.txt"}}, Sources: []Source{}}
}

var sourceID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,48}$`)

func Validate(c Config) error {
	a := c.AutoBan
	if c.Version != 1 || a.Threshold < 2 || a.Threshold > 1000 || a.WindowSeconds < 10 || a.WindowSeconds > 3600 || a.BanSeconds < 60 || a.BanSeconds > 2592000 {
		return errors.New("自动封禁需 2—1000 次、10—3600 秒统计窗口、60 秒—30 天封禁时长")
	}
	if len(a.StatusCodes) == 0 || len(a.StatusCodes) > 100 || len(a.IgnoredPaths) > 64 || len(c.Sources) > MaxSources {
		return errors.New("状态码、排除路径或订阅数量超限")
	}
	for _, s := range a.StatusCodes {
		if s < 400 || s > 499 {
			return errors.New("自动封禁只统计指定的 HTTP 4xx 状态码")
		}
	}
	for _, p := range a.IgnoredPaths {
		if !strings.HasPrefix(p, "/") || len(p) > 256 || strings.ContainsAny(p, "?#\r\n\x00") {
			return errors.New("排除路径需以 / 开始，不包含查询参数；以 / 结尾时匹配路径前缀")
		}
	}
	ids, urls := map[string]bool{}, map[string]bool{}
	for _, s := range c.Sources {
		if !sourceID.MatchString(s.ID) || ids[s.ID] || strings.TrimSpace(s.Name) == "" || len(s.Name) > 100 || s.IntervalHours < 1 || s.IntervalHours > 720 || (s.Format != "plain" && s.Format != "spamhaus") {
			return errors.New("订阅需唯一标识、名称、格式及 1—720 小时更新间隔")
		}
		if err := ValidateURL(s.URL); err != nil {
			return err
		}
		if urls[s.URL] {
			return errors.New("同一订阅地址不能重复添加")
		}
		ids[s.ID], urls[s.URL] = true, true
	}
	return nil
}
func ValidateURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 2048 || (u.Port() != "" && u.Port() != "443") {
		return errors.New("订阅需公开 HTTPS 地址，不带账号、查询令牌、片段或非 443 端口")
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !publicAddress(ip) {
		return errors.New("订阅地址不能指向本机或内网")
	}
	return nil
}
func parsePrefix(s string) (netip.Prefix, error) {
	if ip, e := netip.ParseAddr(s); e == nil {
		if ip.Zone() != "" {
			return netip.Prefix{}, errors.New("不支持带网卡区域的 IP")
		}
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	p, e := netip.ParsePrefix(s)
	if e != nil {
		return p, fmt.Errorf("无效 IP/CIDR：%s", s)
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return p, errors.New("无效映射 IPv4 网段")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}
func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
