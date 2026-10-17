package access

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type FeedState struct {
	ID          string    `json:"id"`
	Count       int       `json:"count"`
	Updating    bool      `json:"updating"`
	LastAttempt time.Time `json:"lastAttempt"`
	LastSuccess time.Time `json:"lastSuccess"`
	NextUpdate  time.Time `json:"nextUpdate"`
	Error       string    `json:"error"`
}
type feed struct {
	source Source
	set    prefixSet
	values []string
	status FeedState
}
type feedCache struct {
	URL    string    `json:"url"`
	Format string    `json:"format"`
	Raw    []byte    `json:"raw"`
	Status FeedState `json:"status"`
}

func (f *feed) state() FeedState {
	s := f.status
	s.ID = f.source.ID
	s.Count = len(f.values)
	if !s.LastAttempt.IsZero() {
		s.NextUpdate = s.LastAttempt.Add(time.Duration(f.source.IntervalHours) * time.Hour)
	}
	return s
}
func Parse(data []byte, format string) ([]string, error) {
	if len(data) == 0 || len(data) > MaxBody {
		return nil, errors.New("订阅内容为空或超过 8 MiB")
	}
	result := []string{}
	seen := map[string]bool{}
	add := func(s string) error {
		p, e := parsePrefix(s)
		if e != nil {
			return errors.New("订阅包含非 IP/CIDR 条目")
		}
		key := p.String()
		if !seen[key] {
			seen[key] = true
			result = append(result, key)
		}
		if len(result) > MaxEntries {
			return errors.New("单个订阅超过 50000 条")
		}
		return nil
	}
	switch format {
	case "plain":
		scan := bufio.NewScanner(bytes.NewReader(data))
		scan.Buffer(make([]byte, 4096), 65536)
		for scan.Scan() {
			s := strings.TrimSpace(strings.TrimPrefix(scan.Text(), "\ufeff"))
			if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
				continue
			}
			if i := strings.IndexAny(s, "#;"); i >= 0 {
				s = strings.TrimSpace(s[:i])
			}
			if e := add(s); e != nil {
				return nil, e
			}
		}
		if e := scan.Err(); e != nil {
			return nil, e
		}
	case "spamhaus":
		dec := json.NewDecoder(bytes.NewReader(data))
		for {
			var row map[string]json.RawMessage
			e := dec.Decode(&row)
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, errors.New("Spamhaus JSON 格式无效")
			}
			var cidr string
			if v, ok := row["cidr"]; ok {
				if json.Unmarshal(v, &cidr) != nil {
					return nil, errors.New("CIDR 字段无效")
				}
				if e := add(cidr); e != nil {
					return nil, e
				}
			} else if _, ok := row["type"]; !ok {
				return nil, errors.New("未识别的 Spamhaus JSON 条目")
			}
		}
	default:
		return nil, errors.New("不支持的订阅格式")
	}
	if len(result) == 0 {
		return nil, errors.New("订阅没有有效 IP/CIDR，保留旧名单")
	}
	return result, nil
}
func secureClient() *http.Client {
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		if len(ips) == 0 {
			return nil, errors.New("订阅域名没有 IP")
		}
		for _, ip := range ips {
			if !publicAddress(ip) {
				return nil, errors.New("订阅 DNS 解析到本机、内网或保留地址，已阻止")
			}
		}
		d := net.Dialer{Timeout: 10 * time.Second}
		var last error
		for _, ip := range ips {
			c, e := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return c, nil
			}
			last = e
		}
		return nil, last
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: dial, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxIdleConns: 2}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("订阅重定向过多")
		}
		return ValidateURL(r.URL.String())
	}}
}
func fetch(ctx context.Context, src Source) ([]byte, error) {
	if e := ValidateURL(src.URL); e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if e != nil {
		return nil, e
	}
	r.Header.Set("User-Agent", "LinkNest/1.1.0 IP-feed")
	client := secureClient()
	defer client.CloseIdleConnections()
	res, e := client.Do(r)
	if e != nil {
		return nil, errors.New("订阅请求失败：" + safeError(e.Error(), src.URL))
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("订阅服务器返回 HTTP %d", res.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(res.Body, MaxBody+1))
	if e != nil {
		return nil, e
	}
	if len(data) > MaxBody {
		return nil, errors.New("订阅超过 8 MiB")
	}
	return data, nil
}
func safeError(s, url string) string {
	s = strings.ReplaceAll(s, url, "订阅地址")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
func (m *Manager) loadFeed(s Source) *feed {
	f := &feed{source: s, set: newPrefixSet(nil), status: FeedState{ID: s.ID}}
	path := filepath.Join(m.dir, "subscriptions", s.ID+".json")
	data, e := readCache(path)
	if e != nil {
		return f
	}
	var c feedCache
	if json.Unmarshal(data, &c) != nil || c.URL != s.URL || c.Format != s.Format {
		return f
	}
	f.status = c.Status
	f.status.Updating = false
	if len(c.Raw) > 0 {
		values, e := Parse(c.Raw, s.Format)
		if e != nil {
			f.status.Error = "订阅缓存无效"
			return f
		}
		f.values = values
		f.set = newPrefixSet(values)
	}
	return f
}

// Update starts at most two independent requests; failed sources retain their old list.
func (m *Manager) Update(ctx context.Context, id string) error {
	m.mu.Lock()
	f := m.feeds[id]
	if f == nil || !f.source.Enabled {
		m.mu.Unlock()
		return errors.New("订阅不存在或未启用")
	}
	if f.status.Updating || m.active >= 2 {
		m.mu.Unlock()
		return errors.New("已有订阅正在更新，请稍后再试")
	}
	// Respect source publication policy even for repeated manual clicks and restarts.
	if !f.status.LastAttempt.IsZero() && m.now().Sub(f.status.LastAttempt) < time.Hour {
		m.mu.Unlock()
		return errors.New("每个订阅每小时最多请求一次")
	}
	f.status.LastAttempt = m.now()
	f.status.Updating = true
	m.active++
	src := f.source
	status := f.status
	// Persist cooldown before issuing a network request, preserving the last raw list.
	path := filepath.Join(m.dir, "subscriptions", src.ID+".json")
	cache := feedCache{URL: src.URL, Format: src.Format, Status: status}
	if old, e := readCache(path); e == nil {
		var c feedCache
		if json.Unmarshal(old, &c) == nil && c.URL == src.URL && c.Format == src.Format {
			cache.Raw = c.Raw
		}
	}
	data, _ := json.Marshal(cache)
	if e := atomicWrite(path, data); e != nil {
		m.active--
		f.status.Updating = false
		f.status.Error = "无法保存订阅状态：" + e.Error()
		m.mu.Unlock()
		return e
	}
	m.mu.Unlock()
	raw, e := m.fetch(ctx, src)
	var values []string
	if e == nil {
		values, e = Parse(raw, src.Format)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active--
	f.status.Updating = false
	if m.feeds[id] != f {
		return nil
	}
	if e == nil {
		total := len(values)
		for k, v := range m.feeds {
			if k != id {
				total += len(v.values)
			}
		}
		if total > 200000 {
			e = errors.New("全部订阅合计超过 200000 条")
		}
	}
	previousSuccess := f.status.LastSuccess
	if e != nil {
		f.status.Error = safeError(e.Error(), src.URL)
	} else {
		cache.Raw = raw
		f.status.LastSuccess = m.now()
		f.status.Error = ""
	}
	cache.Status = f.status
	data, _ = json.Marshal(cache)
	if pe := atomicWrite(path, data); pe != nil {
		f.status.LastSuccess = previousSuccess
		f.status.Error = "缓存保存失败：" + pe.Error()
		return pe
	}
	if e == nil {
		f.values = values
		f.set = newPrefixSet(values)
	}
	return e
}

func readCache(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if info.Size() > 12<<20 {
		return nil, errors.New("订阅缓存过大")
	}
	b, e := io.ReadAll(io.LimitReader(f, (12<<20)+1))
	if len(b) > 12<<20 {
		return nil, errors.New("订阅缓存过大")
	}
	return b, e
}

// Tick is called by the application scheduler; constructors and tests do not access the network.
func (m *Manager) Tick(ctx context.Context) {
	_ = m.Flush()
	m.mu.Lock()
	due := []string{}
	now := m.now()
	for _, s := range m.cfg.Sources {
		f := m.feeds[s.ID]
		if s.Enabled && !f.status.Updating && (f.status.LastAttempt.IsZero() || !now.Before(f.status.LastAttempt.Add(time.Duration(s.IntervalHours)*time.Hour))) {
			due = append(due, s.ID)
		}
	}
	m.mu.Unlock()
	for _, id := range due {
		if ctx.Err() != nil {
			return
		}
		_ = m.Update(ctx, id)
	}
}

// Never permit subscription requests to reserved/metadata networks.
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2001::/32"),
}
