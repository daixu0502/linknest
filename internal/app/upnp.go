package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

type UPnPBlock struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}
type UPnPConfig struct {
	Enabled              bool        `json:"enabled"`
	DescriptionURL       string      `json:"descriptionUrl"`
	Interface            string      `json:"interface"`
	LANZone              string      `json:"lanZone"`
	WritePolicy          string      `json:"writePolicy"`
	WritePolicyUpdatedAt string      `json:"writePolicyUpdatedAt,omitempty"`
	Blacklist            []UPnPBlock `json:"blacklist"`
}
type UPnPMapping struct {
	RemoteHost   string `json:"remoteHost"`
	ExternalPort int    `json:"externalPort"`
	Protocol     string `json:"protocol"`
	InternalIP   string `json:"internalIP"`
	InternalPort int    `json:"internalPort"`
	Enabled      bool   `json:"enabled"`
	Description  string `json:"description"`
	LeaseSeconds int    `json:"leaseSeconds"`
}
type UPnPManager struct {
	mu            sync.Mutex
	op            sync.Mutex
	store         *Store
	config        UPnPConfig
	loadError     string
	appliedDigest string
	appliedAt     string
	clientFactory func(UPnPConfig) (*http.Client, error)
}
type upnpDisk struct {
	Config        UPnPConfig `json:"config"`
	AppliedDigest string     `json:"appliedDigest,omitempty"`
	AppliedAt     string     `json:"appliedAt,omitempty"`
}

func newUPnP(s *Store) *UPnPManager {
	u := &UPnPManager{store: s, config: UPnPConfig{LANZone: "lan", WritePolicy: "own", Blacklist: []UPnPBlock{}}, clientFactory: upnpHTTPClient}
	b, err := os.ReadFile(filepath.Join(s.dir, "upnp", "config.json"))
	if errors.Is(err, os.ErrNotExist) {
		return u
	}
	var d upnpDisk
	if err != nil || json.Unmarshal(b, &d) != nil {
		u.loadError = "UPnP 配置无法读取；未执行任何路由器操作"
		return u
	}
	if err := validateUPnPConfig(&d.Config); err != nil {
		u.loadError = "UPnP 配置校验失败：" + err.Error()
		return u
	}
	u.config, u.appliedDigest, u.appliedAt = d.Config, d.AppliedDigest, d.AppliedAt
	return u
}
func (u *UPnPManager) snapshot() (UPnPConfig, string, string, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	c := u.config
	c.Blacklist = append([]UPnPBlock{}, c.Blacklist...)
	return c, u.appliedDigest, u.appliedAt, u.loadError
}
func (u *UPnPManager) save(c UPnPConfig, digest, at string) error {
	if err := validateUPnPConfig(&c); err != nil {
		return err
	}
	b, err := json.MarshalIndent(upnpDisk{c, digest, at}, "", "  ")
	if err != nil {
		return err
	}
	if err = writeAtomic(filepath.Join(u.store.dir, "upnp", "config.json"), b); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.config, u.appliedDigest, u.appliedAt, u.loadError = c, digest, at, ""
	return nil
}
func upnpEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host == "" {
		return nil, errors.New("设备描述地址需为内网 HTTP 地址，不可含账号、查询参数或片段")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || ip.To4() == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
		return nil, errors.New("仅支持内网或回环 IPv4 字面地址，禁止公网地址及域名")
	}
	if p := u.Port(); p != "" {
		v, e := strconv.Atoi(p)
		if e != nil || v < 1 || v > 65535 {
			return nil, errors.New("UPnP HTTP 端口无效")
		}
	}
	if u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return nil, errors.New("请填写完整的设备描述路径，例如 /rootDesc.xml")
	}
	return u, nil
}
func validateUPnPConfig(c *UPnPConfig) error {
	if c.WritePolicy == "" {
		c.WritePolicy = "own"
	}
	if c.WritePolicy != "own" && c.WritePolicy != "service" {
		return errors.New("UPnP 写权限策略无效")
	}
	if c.LANZone == "" {
		c.LANZone = "lan"
	}
	if len(c.LANZone) > 24 || !validID.MatchString(c.LANZone) {
		return errors.New("LAN 防火墙区域名称无效")
	}
	if c.DescriptionURL != "" || c.Enabled {
		if _, err := upnpEndpoint(c.DescriptionURL); err != nil {
			return err
		}
	}
	if len(c.Interface) > 32 || strings.ContainsAny(c.Interface, " /\\\t\r\n\x00") {
		return errors.New("网卡名称无效")
	}
	if len(c.Blacklist) > 128 {
		return errors.New("最多配置 128 条设备黑名单")
	}
	ids, addresses := map[string]bool{}, map[string]bool{}
	for i := range c.Blacklist {
		b := &c.Blacklist[i]
		if !validID.MatchString(b.ID) || ids[b.ID] || len(b.Name) > 100 || strings.ContainsAny(b.Name, "\r\n\x00") {
			return errors.New("黑名单名称或标识无效/重复")
		}
		ids[b.ID] = true
		address, _, err := upnpBlockAddress(b.Address)
		if err != nil {
			return err
		}
		b.Address = address
		if addresses[address] {
			return errors.New("黑名单地址重复")
		}
		addresses[address] = true
	}
	return nil
}
func upnpBlockAddress(s string) (string, bool, error) {
	s = strings.TrimSpace(s)
	if m, err := parseWOLMAC(s); err == nil && len(m) == 6 {
		if m[0]&1 != 0 || m.String() == "00:00:00:00:00:00" {
			return "", false, errors.New("黑名单 MAC 需为有效的单播设备地址")
		}
		return strings.ToUpper(m.String()), true, nil
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil && ip.IsPrivate() {
		return ip.String() + "/32", false, nil
	}
	if ip, n, err := net.ParseCIDR(s); err == nil && ip.To4() != nil && ip.IsPrivate() {
		ones, bits := n.Mask.Size()
		if bits == 32 && ones >= 8 && net.IP(n.IP).IsPrivate() {
			// Require the entire CIDR to stay within a private block.
			last := append(net.IP(nil), n.IP.To4()...)
			for i := range last {
				last[i] |= ^n.Mask[i]
			}
			if last.IsPrivate() {
				return n.String(), false, nil
			}
		}
	}
	return "", false, errors.New("黑名单请填写私网 IPv4、私网网段或设备 MAC 地址")
}
func upnpPolicyDigest(c UPnPConfig) string {
	// Management on/off does not silently revoke a persistent router policy.
	b, _ := json.Marshal(struct {
		URL, Zone string
		Rules     []UPnPBlock
	}{c.DescriptionURL, c.LANZone, c.Blacklist})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type upnpSOAPError struct {
	Code    int
	Message string
}

func (e *upnpSOAPError) Error() string {
	hint := ""
	switch e.Code {
	case 606:
		hint = "；服务拒绝授权，可能启用了只允许管理本机映射的安全模式"
	case 718:
		hint = "；端口冲突，或原厂安全模式拒绝管理其他设备的映射"
	case 725:
		hint = "；路由器仅支持永久租期（填写 0）"
	}
	return fmt.Sprintf("UPnP 错误 %d：%s%s", e.Code, e.Message, hint)
}

type upnpService struct {
	client        *http.Client
	kind, control string
	localIP       string
}

func upnpHTTPClient(c UPnPConfig) (*http.Client, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	if c.Interface != "" {
		if err := upnpBindInterface(&d, c.Interface); err != nil {
			return nil, err
		}
	}
	t := &http.Transport{Proxy: nil, DialContext: d.DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: 4 * time.Second, MaxResponseHeaderBytes: 16384}
	return &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("禁止 UPnP 请求重定向") }}, nil
}
func upnpRead(client *http.Client, ctx context.Context, method, target string, body io.Reader, headers http.Header) ([]byte, int, error) {
	r, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, 0, err
	}
	r.Header = headers
	response, err := client.Do(r)
	if err != nil {
		return nil, 0, fmt.Errorf("UPnP 请求失败：%w", err)
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if len(b) > 1<<20 {
		return nil, response.StatusCode, errors.New("UPnP 响应超过 1 MiB 限制")
	}
	return b, response.StatusCode, err
}
func discoverUPnP(ctx context.Context, c UPnPConfig, factory func(UPnPConfig) (*http.Client, error)) (*upnpService, error) {
	base, err := upnpEndpoint(c.DescriptionURL)
	if err != nil {
		return nil, err
	}
	client, err := factory(c)
	if err != nil {
		return nil, err
	}
	localIP := ""
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		h, _, _ := net.SplitHostPort(info.Conn.LocalAddr().String())
		localIP = h
	}}
	b, status, err := upnpRead(client, httptrace.WithClientTrace(ctx, trace), "GET", base.String(), nil, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("UPnP 设备描述返回 HTTP %d", status)
	}
	var root struct {
		Base    string       `xml:"URLBase"`
		Devices []upnpDevice `xml:"device"`
	}
	if err = xml.Unmarshal(b, &root); err != nil {
		return nil, errors.New("UPnP 设备描述 XML 无法解析")
	}
	if root.Base != "" {
		ref, e := url.Parse(root.Base)
		if e != nil || ref.Scheme != base.Scheme || ref.Host != base.Host || ref.User != nil {
			return nil, errors.New("拒绝跨地址的 UPnP URLBase")
		}
		base = ref
	}
	var find func([]upnpDevice) *upnpService
	find = func(devices []upnpDevice) *upnpService {
		for _, device := range devices {
			for _, service := range device.Services {
				if service.Kind != "urn:schemas-upnp-org:service:WANIPConnection:1" && service.Kind != "urn:schemas-upnp-org:service:WANIPConnection:2" && service.Kind != "urn:schemas-upnp-org:service:WANPPPConnection:1" {
					continue
				}
				ref, e := url.Parse(service.Control)
				if e != nil || service.Control == "" {
					continue
				}
				target := base.ResolveReference(ref)
				if target.Scheme != base.Scheme || target.Host != base.Host || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
					continue
				}
				return &upnpService{client: client, kind: service.Kind, control: target.String(), localIP: localIP}
			}
			if sub := find(device.Devices); sub != nil {
				return sub
			}
		}
		return nil
	}
	if service := find(root.Devices); service != nil {
		return service, nil
	}
	return nil, errors.New("设备未提供可用的 WANIP/WANPPP 映射管理接口")
}

type upnpDevice struct {
	Services []struct {
		Kind    string `xml:"serviceType"`
		Control string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []upnpDevice `xml:"deviceList>device"`
}

func xmlText(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
func (s *upnpService) call(ctx context.Context, action string, fields ...string) (map[string]string, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + s.kind + `">`)
	for i := 0; i+1 < len(fields); i += 2 {
		fmt.Fprintf(&b, "<%s>%s</%s>", fields[i], xmlText(fields[i+1]), fields[i])
	}
	b.WriteString("</u:" + action + "></s:Body></s:Envelope>")
	headers := http.Header{"Content-Type": {`text/xml; charset="utf-8"`}, "Soapaction": {`"` + s.kind + "#" + action + `"`}}
	data, status, err := upnpRead(s.client, ctx, "POST", s.control, strings.NewReader(b.String()), headers)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Body struct {
			Inner string `xml:",innerxml"`
		} `xml:"Body"`
	}
	if xml.Unmarshal(data, &envelope) != nil {
		return nil, fmt.Errorf("UPnP 返回无效 XML（HTTP %d）", status)
	}
	decoder := xml.NewDecoder(strings.NewReader(envelope.Body.Inner))
	out := map[string]string{}
	response := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("UPnP SOAP 响应无法解析")
		}
		if start, ok := token.(xml.StartElement); ok {
			name := start.Name.Local
			if name == action+"Response" {
				response = true
				continue
			}
			if strings.HasPrefix(name, "New") || name == "errorCode" || name == "errorDescription" {
				var value string
				if decoder.DecodeElement(&value, &start) != nil {
					return nil, errors.New("UPnP 字段无法解析")
				}
				out[name] = value
			}
		}
	}
	if code, err := strconv.Atoi(out["errorCode"]); err == nil {
		return nil, &upnpSOAPError{code, out["errorDescription"]}
	}
	if status != 200 || !response {
		return nil, fmt.Errorf("UPnP %s 未成功（HTTP %d）", action, status)
	}
	return out, nil
}
func upnpMappingFields(m UPnPMapping) []string {
	return []string{"NewRemoteHost", m.RemoteHost, "NewExternalPort", strconv.Itoa(m.ExternalPort), "NewProtocol", m.Protocol}
}
func upnpMappingFrom(fields map[string]string) (UPnPMapping, error) {
	m := UPnPMapping{RemoteHost: fields["NewRemoteHost"], Protocol: strings.ToUpper(fields["NewProtocol"]), InternalIP: fields["NewInternalClient"], Description: fields["NewPortMappingDescription"], Enabled: fields["NewEnabled"] == "1" || fields["NewEnabled"] == "true"}
	m.ExternalPort, _ = strconv.Atoi(fields["NewExternalPort"])
	m.InternalPort, _ = strconv.Atoi(fields["NewInternalPort"])
	m.LeaseSeconds, _ = strconv.Atoi(fields["NewLeaseDuration"])
	if err := validateUPnPMapping(m); err != nil {
		return m, fmt.Errorf("路由器返回无效映射：%w", err)
	}
	return m, nil
}
func validateUPnPMapping(m UPnPMapping) error {
	if m.ExternalPort < 1 || m.ExternalPort > 65535 || m.InternalPort < 1 || m.InternalPort > 65535 || m.Protocol != "TCP" && m.Protocol != "UDP" || m.LeaseSeconds < 0 || int64(m.LeaseSeconds) > 4294967295 {
		return errors.New("映射端口、协议或租期无效")
	}
	ip := net.ParseIP(m.InternalIP)
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		return errors.New("映射目标需为私网 IPv4 地址")
	}
	if m.RemoteHost != "" {
		ip = net.ParseIP(m.RemoteHost)
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("远端来源需为空或单个 IPv4 地址")
		}
	}
	if len(m.Description) > 120 || strings.ContainsAny(m.Description, "\r\n\x00") {
		return errors.New("映射说明过长或含控制字符")
	}
	return nil
}
func (s *upnpService) list(ctx context.Context) ([]UPnPMapping, bool, error) {
	out := []UPnPMapping{}
	for i := 0; i <= 512; i++ {
		fields, err := s.call(ctx, "GetGenericPortMappingEntry", "NewPortMappingIndex", strconv.Itoa(i))
		if err != nil {
			var soap *upnpSOAPError
			if errors.As(err, &soap) && soap.Code == 713 {
				return out, false, nil
			}
			return out, false, err
		}
		if i == 512 {
			return out, true, nil
		}
		m, err := upnpMappingFrom(fields)
		if err != nil {
			return out, false, err
		}
		out = append(out, m)
	}
	return out, true, nil
}
func (s *upnpService) get(ctx context.Context, key UPnPMapping) (UPnPMapping, error) {
	fields, err := s.call(ctx, "GetSpecificPortMappingEntry", upnpMappingFields(key)...)
	if err != nil {
		return UPnPMapping{}, err
	}
	fields["NewRemoteHost"], fields["NewExternalPort"], fields["NewProtocol"] = key.RemoteHost, strconv.Itoa(key.ExternalPort), key.Protocol
	return upnpMappingFrom(fields)
}
func (s *upnpService) add(ctx context.Context, m UPnPMapping) error {
	enabled := "0"
	if m.Enabled {
		enabled = "1"
	}
	_, err := s.call(ctx, "AddPortMapping", append(upnpMappingFields(m), "NewInternalPort", strconv.Itoa(m.InternalPort), "NewInternalClient", m.InternalIP, "NewEnabled", enabled, "NewPortMappingDescription", m.Description, "NewLeaseDuration", strconv.Itoa(m.LeaseSeconds))...)
	return err
}
func (s *upnpService) remove(ctx context.Context, m UPnPMapping) error {
	_, err := s.call(ctx, "DeletePortMapping", upnpMappingFields(m)...)
	return err
}
func sameUPnPMapping(a, b UPnPMapping) bool {
	a.LeaseSeconds, b.LeaseSeconds = 0, 0
	return reflect.DeepEqual(a, b)
}
func (s *upnpService) mutate(ctx context.Context, operation string, before, after UPnPMapping) error {
	if operation != "add" {
		current, err := s.get(ctx, before)
		if err != nil {
			return err
		}
		if !sameUPnPMapping(current, before) {
			return errors.New("映射已被其他设备更改，请刷新后重试")
		}
		// Use the latest remaining lease, not the stale value in the browser.
		before = current
	}
	if operation == "delete" {
		return s.remove(ctx, before)
	}
	if _, err := s.get(ctx, after); err == nil {
		if operation == "add" || before.Protocol != after.Protocol || before.ExternalPort != after.ExternalPort || before.RemoteHost != after.RemoteHost {
			return errors.New("新端口已有映射；不会覆盖其他设备的记录")
		}
	} else {
		var soap *upnpSOAPError
		if !errors.As(err, &soap) || soap.Code != 714 {
			return err
		}
	}
	if operation == "edit" {
		if err := s.remove(ctx, before); err != nil {
			return err
		}
	}
	err := s.add(ctx, after)
	if err == nil {
		actual, check := s.get(ctx, after)
		if check == nil && sameUPnPMapping(actual, after) {
			return nil
		}
		if check != nil {
			err = fmt.Errorf("添加后无法确认状态：%w", check)
		} else {
			err = errors.New("路由器返回的映射与请求不一致，请刷新核对")
		}
	}
	// Never overwrite a concurrent new owner while restoring an edited entry.
	if operation == "edit" {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		if _, check := s.get(rollbackCtx, before); check != nil {
			var soap *upnpSOAPError
			if errors.As(check, &soap) && soap.Code == 714 {
				if restore := s.add(rollbackCtx, before); restore == nil {
					return fmt.Errorf("修改失败，已恢复原映射：%w", err)
				}
			}
		}
		return fmt.Errorf("修改失败，原映射未确认恢复；请刷新并手动核对：%w", err)
	}
	return err
}
