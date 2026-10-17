package app

import (
	"errors"
	"fmt"
	"linknest/internal/access"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Migration is idempotent and preserves enabled states and existing encrypted keys.
// Old fields remain decode-compatible but are cleared after conversion.
func migrateConfig(c *Config) {
	if c.Schema > configSchema {
		return // Never downgrade a future schema before validation.
	}
	if c.Access.Version == 0 {
		c.Access = access.DefaultConfig()
	}
	for i := range c.Devices {
		d := &c.Devices[i]
		d.Name = strings.TrimSpace(d.Name)
		d.Broadcast = strings.TrimSpace(d.Broadcast)
		d.IP = strings.TrimSpace(d.IP)
		if mac, err := parseWOLMAC(d.MAC); err == nil {
			d.MAC = strings.ToUpper(mac.String())
		}
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Kind == "web" && len(r.Routes) == 0 && r.Target != "" {
			domains := []string{}
			if r.Domain != "" {
				domains = append(domains, r.Domain)
			}
			r.Routes = []WebRoute{{ID: migrationID("route", r.ID), Name: r.Name, Enabled: true, Domains: domains, Target: r.Target}}
			r.Target = ""
			r.Domain = ""
		}
	}
	for i := range c.DDNS {
		d := &c.DDNS[i]
		if len(d.Records) == 0 && d.Zone != "" {
			name := d.Zone
			if d.RR != "@" {
				name = d.RR + "." + d.Zone
			}
			value := "{ipv4Addr}"
			if d.Type == "AAAA" {
				value = "{ipv6Addr}"
				d.IPv6 = IPSource{Mode: "url", URL: d.SourceURL}
			} else {
				d.IPv4 = IPSource{Mode: "url", URL: d.SourceURL}
			}
			d.Records = []DDNSRecord{{ID: migrationID("record", d.ID), Name: d.Name, Enabled: true, Zone: d.Zone, Domain: name, Type: d.Type, Value: value, TTL: 600, Line: "default"}}
			d.Zone = ""
			d.RR = ""
			d.Type = ""
			d.SourceURL = ""
		}
		if d.Interval == 0 {
			d.Interval = 300
		}
		if d.IPv4.Mode == "" {
			d.IPv4.Mode = "auto"
		}
		if d.IPv6.Mode == "" {
			d.IPv6.Mode = "auto"
		}
		if d.Records == nil {
			d.Records = []DDNSRecord{}
		}
		for j := range d.Records {
			if d.Records[j].Source.Mode == "" {
				d.Records[j].Source = d.IPv4
				if d.Records[j].Type == "AAAA" {
					d.Records[j].Source = d.IPv6
				}
			}
		}
	}
	c.Schema = configSchema
}
func migrationID(prefix, id string) string {
	if len(id) > 34 {
		id = id[:34]
	}
	return prefix + "_" + id
}
func validateNetwork(r Rule) error {
	h, _, _ := hostPort(r.Listen)
	ip := net.ParseIP(h)
	switch r.Network {
	case "":
		return nil // v0.1 binding semantics
	case "ipv4":
		if h != "" && (ip == nil || ip.To4() == nil) {
			return errors.New("IPv4 监听需填写 IPv4 地址")
		}
	case "ipv6":
		if h != "" && (ip == nil || ip.To4() != nil) {
			return errors.New("IPv6 监听需填写 IPv6 地址")
		}
	case "dual":
		if h != "" && h != "::" {
			return errors.New("双栈监听请留空监听 IP（使用 [::]）")
		}
	default:
		return errors.New("未知网络栈")
	}
	return nil
}
func listenNetwork(r Rule, proto string) string {
	if r.Network == "ipv4" {
		return proto + "4"
	}
	if r.Network == "ipv6" {
		return proto + "6"
	}
	return proto
}
func validateWeb(r Rule, checkID func(string) error) error {
	if len(r.Routes) > 128 {
		return errors.New("每个反代主规则最多 128 条子规则")
	}
	domains := map[string]bool{}
	h, p, _ := hostPort(r.Listen)
	for _, sub := range r.Routes {
		if err := checkID(sub.ID); err != nil {
			return err
		}
		if strings.TrimSpace(sub.Name) == "" {
			return errors.New("子规则名称不能为空")
		}
		if len(sub.Domains) > 32 {
			return errors.New("每条子规则最多 32 个域名")
		}
		hosts := sub.Domains
		if len(hosts) == 0 {
			hosts = []string{"*"}
		}
		for _, d := range hosts {
			d = strings.ToLower(d)
			if d != "*" && !domainRE.MatchString(d) && net.ParseIP(strings.Trim(d, "[]")) == nil {
				return errors.New("前端域名格式错误；请勿包含协议和端口")
			}
			if sub.Enabled && domains[d] {
				return errors.New("同一主规则存在重复启用的前端域名")
			}
			if sub.Enabled {
				domains[d] = true
			}
		}
		if sub.Backend == "bookmarks" || sub.Backend == "wol" {
			continue
		}
		if sub.Backend != "" && sub.Backend != "proxy" {
			return errors.New("未知反向代理后端类型")
		}
		u, err := proxyTargetURL(sub.Target)
		if err != nil {
			return err
		}
		tp := u.Port()
		if tp == "" {
			tp = "80"
			if u.Scheme == "https" {
				tp = "443"
			}
		}
		if r.Enabled && sub.Enabled && tp == strconv.Itoa(p) && (u.Hostname() == h || u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1") {
			return errors.New("反代后端不能指向自身监听端口")
		}
	}
	return nil
}
func validateDDNSTask(d DDNSRule, c Config, checkID func(string) error) error {
	if strings.TrimSpace(d.Name) == "" || d.Interval < 60 || d.Interval > 86400 || d.StartDelay < 0 || d.StartDelay > 3600 {
		return errors.New("DDNS 名称必填；检查间隔 60—86400 秒，启动延迟 0—3600 秒")
	}
	if len(d.Records) > 64 {
		return errors.New("每个 DDNS 任务最多 64 条记录")
	}
	for _, rec := range d.Records {
		if rec.Value != "{ipv4Addr}" && rec.Value != "{ipv6Addr}" {
			continue
		}
		src := rec.Source
		switch src.Mode {
		case "auto":
		case "interface":
			if src.Interface == "" {
				return errors.New("请选择网卡名称")
			}
		case "url":
			u, e := url.Parse(src.URL)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
				return errors.New("IP 检测接口需为 HTTPS")
			}
		default:
			return errors.New("未知 IP 检测方式")
		}
	}
	for _, r := range d.Records {
		if err := checkID(r.ID); err != nil {
			return err
		}
		if (r.Zone != "" && (!domainRE.MatchString(r.Zone) || strings.HasPrefix(r.Zone, "*."))) || !validDNSOwner(r.Domain) {
			return errors.New("DNS 主域名或完整域名无效")
		}
		if r.Zone != "" && r.Domain != r.Zone && !strings.HasSuffix(r.Domain, "."+r.Zone) {
			return errors.New("解析域名不属于指定的 DNS 主域名")
		}
		if r.TTL < 60 || r.TTL > 86400 {
			return errors.New("TTL 需为 60—86400 秒；实际下限由阿里云套餐决定")
		}
		if r.Line == "" || len(r.Line) > 64 || strings.ContainsAny(r.Line, " \r\n") {
			return errors.New("DNS 线路标识无效")
		}
		if _, err := recordValue(r, "8.8.8.8", "2606:4700:4700::1111"); err != nil {
			return err
		}
	}
	_, err := taskAccount(c, d.ID)
	return err
}

// A blank credential reference uses this task's credentials, falling back to
// the explicitly shared/legacy account. References are resolved without copying secrets.
func taskAccount(c Config, id string) (DNSAccount, error) {
	seen := map[string]bool{}
	for id != "" {
		if id == "@shared" {
			return c.DNS, nil
		}
		if seen[id] {
			return DNSAccount{}, errors.New("DDNS 凭据引用形成循环")
		}
		seen[id] = true
		found := false
		for _, d := range c.DDNS {
			if d.ID == id {
				found = true
				if d.CredentialRef != "" {
					id = d.CredentialRef
				} else {
					if d.Account.AccessKeyID != "" || d.Account.Secret != "" {
						return d.Account, nil
					}
					return c.DNS, nil
				}
				break
			}
		}
		if !found {
			return DNSAccount{}, errors.New("引用的 DDNS 凭据任务不存在")
		}
	}
	return c.DNS, nil
}
func (s *Store) dnsAccount(id string) (DNSAccount, error) {
	a, e := taskAccount(s.snapshot(), id)
	if e != nil {
		return a, e
	}
	a.Secret, e = s.unseal(a.Secret)
	return a, e
}
func redactedConfig(c Config) (Config, map[string]bool) {
	flags := map[string]bool{}
	for i := range c.DDNS {
		a, e := taskAccount(c, c.DDNS[i].ID)
		flags[c.DDNS[i].ID] = e == nil && a.Secret != ""
	}
	c.DNS.Secret = ""
	for i := range c.Rules {
		for j := range c.Rules[i].Routes {
			c.Rules[i].Routes[j].AccessPassword = ""
		}
	}
	for i := range c.DDNS {
		c.DDNS[i].Account.Secret = ""
	}
	return c, flags
}
func recordValue(r DDNSRecord, v4, v6 string) (string, error) {
	v := r.Value
	if v == "{ipv4Addr}" {
		v = v4
	}
	if v == "{ipv6Addr}" {
		v = v6
	}
	if v == "" {
		return "", fmt.Errorf("%s：所需地址尚未获取", r.Domain)
	}
	switch r.Type {
	case "A", "AAAA":
		ip := net.ParseIP(v)
		if !publicIP(ip) || (ip.To4() != nil) != (r.Type == "A") {
			return "", errors.New("A/AAAA 内容需为对应公网 IP 或 {ipv4Addr} / {ipv6Addr}")
		}
		v = ip.String()
	case "CNAME":
		if !dnsTarget(v) {
			return "", errors.New("CNAME 内容需为域名")
		}
	default:
		if err := validateStaticDNSValue(r); err != nil {
			return "", err
		}
	}
	return v, nil
}
