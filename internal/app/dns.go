package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type dnsRecord struct {
	ID       string `json:"RecordId"`
	RR       string `json:"RR"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	TTL      int    `json:"TTL"`
	Line     string `json:"Line"`
	Priority int    `json:"Priority"`
}
type aliResult struct {
	Code     string `json:"Code"`
	Message  string `json:"Message"`
	RecordID string `json:"RecordId"`
	Total    int    `json:"TotalCount"`
	Records  struct {
		Items []dnsRecord `json:"Record"`
	} `json:"DomainRecords"`
	Domains struct {
		Items []struct {
			Name string `json:"DomainName"`
		} `json:"Domain"`
	} `json:"Domains"`
}
type AliDNS struct {
	ID, Secret string
	Client     *http.Client
	Endpoint   string
}

func encodeAli(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
func aliSignature(v url.Values, secret string) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, k := range keys {
		parts = append(parts, encodeAli(k)+"="+encodeAli(v.Get(k)))
	}
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte("POST&%2F&" + encodeAli(strings.Join(parts, "&"))))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
func (a AliDNS) call(ctx context.Context, action string, params map[string]string) (aliResult, error) {
	var out aliResult
	if a.ID == "" || a.Secret == "" {
		return out, errors.New("请先配置阿里云 AccessKey")
	}
	v := url.Values{"Format": {"JSON"}, "Version": {"2015-01-09"}, "AccessKeyId": {a.ID}, "SignatureMethod": {"HMAC-SHA1"}, "Timestamp": {time.Now().UTC().Format("2006-01-02T15:04:05Z")}, "SignatureVersion": {"1.0"}, "SignatureNonce": {token(16)}, "Action": {action}}
	for k, x := range params {
		v.Set(k, x)
	}
	v.Set("Signature", aliSignature(v, a.Secret))
	endpoint := a.Endpoint
	if endpoint == "" {
		endpoint = "https://alidns.aliyuncs.com/"
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil}}
	}
	res, err := client.Do(req)
	if err != nil {
		return out, errors.New("连接阿里云 DNS API 失败，请检查出网和系统时间")
	}
	defer res.Body.Close()
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return out, errors.New("阿里云返回了无法解析的数据")
	}
	if out.Code != "" {
		return out, fmt.Errorf("阿里云 API：%s", out.Code)
	}
	if res.StatusCode != 200 {
		return out, fmt.Errorf("阿里云 HTTP %d", res.StatusCode)
	}
	return out, nil
}
func (a AliDNS) find(ctx context.Context, zone, rr, kind string) ([]dnsRecord, error) {
	out, err := a.call(ctx, "DescribeDomainRecords", map[string]string{"DomainName": zone, "RRKeyWord": rr, "TypeKeyWord": kind, "SearchMode": "EXACT", "PageSize": "500"})
	if err != nil {
		return nil, err
	}
	if out.Total > 500 {
		return nil, errors.New("查询结果过多，拒绝不完整匹配")
	}
	records := []dnsRecord{}
	for _, r := range out.Records.Items {
		if r.RR == rr && r.Type == kind {
			records = append(records, r)
		}
	}
	return records, nil
}
func (a AliDNS) upsert(ctx context.Context, zone, rr, kind, value string) (bool, error) {
	return a.upsertRecord(ctx, zone, rr, kind, value, 600, "default")
}

// Delete exactly one record in the selected routing line, never a whole RR set.
func (a AliDNS) deleteRecord(ctx context.Context, rec DDNSRecord) (bool, error) {
	zone := rec.Zone
	if zone == "" {
		zones, err := a.zones(ctx)
		if err != nil {
			return false, err
		}
		zone, err = matchDNSZone(rec.Domain, zones)
		if err != nil {
			return false, err
		}
	}
	rr := strings.TrimSuffix(rec.Domain, "."+zone)
	if rec.Domain == zone {
		rr = "@"
	}
	items, err := a.find(ctx, zone, rr, rec.Type)
	if err != nil {
		return false, err
	}
	line := rec.Line
	if line == "" {
		line = "default"
	}
	var selected []dnsRecord
	for _, r := range items {
		if r.Line == line || r.Line == "" && line == "default" {
			selected = append(selected, r)
		}
	}
	if len(selected) == 0 {
		return false, nil
	}
	if len(selected) != 1 || selected[0].ID == "" {
		return false, errors.New("同名、同类型、同线路记录不唯一，未删除远端记录；请在阿里云控制台核对")
	}
	_, err = a.call(ctx, "DeleteDomainRecord", map[string]string{"RecordId": selected[0].ID})
	if err != nil {
		return false, fmt.Errorf("远端删除失败，请核对 DeleteDomainRecord 权限；本地配置保留：%w", err)
	}
	return true, nil
}
func (a AliDNS) upsertRecord(ctx context.Context, zone, rr, kind, value string, ttl int, line string, priority ...int) (bool, error) {
	mx := 1
	if len(priority) > 0 {
		mx = priority[0]
	}
	items, err := a.find(ctx, zone, rr, kind)
	if err != nil {
		return false, err
	}
	selected := []dnsRecord{}
	for _, r := range items {
		if r.Line == line || (r.Line == "" && line == "default") {
			selected = append(selected, r)
		}
	}
	items = selected
	if len(items) > 1 {
		return false, errors.New("存在多条同名同类型记录，拒绝覆盖；请先明确保留哪条")
	}
	p := map[string]string{"RR": rr, "Type": kind, "Value": value, "TTL": strconv.Itoa(ttl), "Line": line}
	if kind == "MX" {
		p["Priority"] = strconv.Itoa(mx)
	}
	action := "AddDomainRecord"
	if len(items) == 1 {
		if items[0].Value == value && (items[0].TTL == ttl || items[0].TTL == 0 && ttl == 600) && (kind != "MX" || items[0].Priority == mx) {
			return false, nil
		}
		p["RecordId"] = items[0].ID
		action = "UpdateDomainRecord"
	} else {
		p["DomainName"] = zone
	}
	_, err = a.call(ctx, action, p)
	return err == nil, err
}

// Use provider-owned zones, never guess the last two labels (co.uk, delegated zones).
func (a AliDNS) zones(ctx context.Context) ([]string, error) {
	zones := []string{}
	for page := 1; page <= 100; page++ {
		out, e := a.call(ctx, "DescribeDomains", map[string]string{"PageSize": "100", "PageNumber": strconv.Itoa(page)})
		if e != nil {
			return nil, fmt.Errorf("自动识别主域名失败（需要 DescribeDomains 权限），请手动填写：%w", e)
		}
		for _, z := range out.Domains.Items {
			zones = append(zones, strings.ToLower(z.Name))
		}
		if page*100 >= out.Total {
			return zones, nil
		}
	}
	return nil, errors.New("账户域名超过自动识别上限，请手动填写主域名")
}
func matchDNSZone(domain string, zones []string) (string, error) {
	best := ""
	for _, z := range zones {
		if (domain == z || strings.HasSuffix(domain, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	if best == "" {
		return "", errors.New("未找到有权限的托管主域名，请手动填写并核对阿里云账户")
	}
	return best, nil
}

type JobStatus struct {
	ID      string         `json:"id"`
	State   string         `json:"state"`
	Message string         `json:"message"`
	Updated string         `json:"updated"`
	Next    string         `json:"next,omitempty"`
	IPv4    string         `json:"ipv4,omitempty"`
	IPv6    string         `json:"ipv6,omitempty"`
	Records []RecordStatus `json:"records,omitempty"`
}
