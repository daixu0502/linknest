package app

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var dnsLabelRE = regexp.MustCompile(`^[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$`)
var caaValueRE = regexp.MustCompile(`^[0-9]{1,3}\s+[a-zA-Z0-9]+\s+"[^"\r\n]*"$`)

func validDNSOwner(v string) bool {
	if len(v) > 253 {
		return false
	}
	v = strings.TrimPrefix(v, "*.")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !dnsLabelRE.MatchString(p) {
			return false
		}
	}
	return true
}
func dnsTarget(v string) bool {
	return domainRE.MatchString(strings.TrimSuffix(v, ".")) && !strings.HasPrefix(v, "*.")
}
func dnsUint(v string, max int) bool { n, e := strconv.Atoi(v); return e == nil && n >= 0 && n <= max }
func validateStaticDNSValue(r DDNSRecord) error {
	v := r.Value
	if len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") || v == "{ipv4Addr}" || v == "{ipv6Addr}" {
		return errors.New("该类型需填写静态解析内容（单行，最多 4096 字节）")
	}
	switch r.Type {
	case "MX":
		if !dnsTarget(v) || r.Priority < 1 || r.Priority > 50 {
			return errors.New("MX 需填写邮件服务器域名，优先级范围为 1—50")
		}
	case "NS", "PTR":
		if !dnsTarget(v) {
			return fmt.Errorf("%s 内容需为目标域名", r.Type)
		}
	case "TXT":
		if strings.TrimSpace(v) == "" {
			return errors.New("TXT 内容不能为空")
		}
	case "SRV":
		p := strings.Fields(v)
		if len(p) != 4 || !dnsUint(p[0], 65535) || !dnsUint(p[1], 65535) || !dnsUint(p[2], 65535) || !(p[3] == "." || dnsTarget(p[3])) {
			return errors.New("SRV 格式：优先级 权重 端口 目标域名，例如 0 5 443 server.example.com")
		}
	case "CAA":
		p := strings.Fields(v)
		if !caaValueRE.MatchString(v) || !dnsUint(p[0], 255) {
			return errors.New("CAA 格式：标志 标签 \"值\"，例如 0 issue \"letsencrypt.org\"")
		}
	case "SVCB", "HTTPS":
		p := strings.Fields(v)
		if len(p) < 2 || !dnsUint(p[0], 65535) || !(p[1] == "." || dnsTarget(p[1])) || (p[0] == "0" && (len(p) != 2 || p[1] == ".")) {
			return errors.New("SVCB/HTTPS 格式：优先级 目标域名 参数，例如 1 . alpn=\"h2,h3\"；别名模式 0 不带参数")
		}
	case "REDIRECT_URL", "FORWARD_URL":
		u, e := url.Parse(v)
		if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return errors.New("URL 转发内容需为不含账号密码的 HTTP/HTTPS 地址")
		}
	default:
		return errors.New("不支持此 DNS 记录类型")
	}
	return nil
}
