package access

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

type Ban struct {
	IP      string    `json:"ip"`
	Kind    string    `json:"kind"`
	Reason  string    `json:"reason"`
	Hits    int       `json:"hits"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}
type State struct {
	Bans             []Ban       `json:"bans"`
	Sources          []FeedState `json:"sources"`
	PersistenceError string      `json:"persistenceError"`
}
type Manager struct {
	active       int
	events       int
	lastPrune    time.Time
	fetch        func(context.Context, Source) ([]byte, error)
	mu           sync.Mutex
	dir          string
	cfg          Config
	white        prefixSet
	bans         map[string]Ban
	counters     map[string][]time.Time
	feeds        map[string]*feed
	dirty        bool
	persistError string
	now          func() time.Time
}

func New(dir string) *Manager {
	m := &Manager{dir: dir, cfg: DefaultConfig(), bans: map[string]Ban{}, counters: map[string][]time.Time{}, feeds: map[string]*feed{}, now: time.Now}
	m.fetch = fetch
	path := filepath.Join(dir, "bans.json")
	info, statErr := os.Stat(path)
	if statErr == nil && info.Size() > 2<<20 {
		m.persistError = "封禁缓存过大，未载入"
		return m
	}
	if b, e := os.ReadFile(path); e == nil {
		var entries []Ban
		if len(b) > 2<<20 || json.Unmarshal(b, &entries) != nil || len(entries) > MaxBans {
			m.persistError = "封禁缓存无效，未载入"
		} else {
			for _, v := range entries {
				ip, e := netip.ParseAddr(v.IP)
				if e == nil && (v.Kind == "auto" || v.Kind == "manual") && (v.Expires.IsZero() || v.Expires.After(m.now())) {
					v.IP = ip.Unmap().String()
					m.bans[v.IP] = v
				}
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		m.persistError = e.Error()
	}
	return m
}
func (m *Manager) Configure(c Config, whitelist []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Version == 0 {
		c = DefaultConfig()
	}
	if !reflect.DeepEqual(m.cfg.AutoBan, c.AutoBan) {
		m.counters = map[string][]time.Time{}
		m.events = 0
	}
	m.cfg = c
	m.white = newPrefixSet(whitelist)
	next := map[string]*feed{}
	for _, s := range c.Sources {
		f := m.feeds[s.ID]
		if f == nil || f.source.URL != s.URL || f.source.Format != s.Format {
			f = m.loadFeed(s)
		}
		f.source = s
		next[s.ID] = f
	}
	total := 0
	for _, s := range c.Sources {
		f := next[s.ID]
		total += len(f.values)
		if total > 200000 {
			total -= len(f.values)
			f.values = nil
			f.set = newPrefixSet(nil)
			f.status.Error = "缓存合计超过 200000 条，未加载此源"
		}
	}
	for id := range m.feeds {
		if next[id] == nil {
			if err := os.Remove(filepath.Join(m.dir, "subscriptions", id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				m.persistError = "清理已删除订阅缓存失败：" + err.Error()
			}
		}
	}
	m.feeds = next
}
func Address(remote string) netip.Addr {
	h, _, e := net.SplitHostPort(remote)
	if e != nil {
		h = remote
	}
	ip, _ := netip.ParseAddr(h)
	return ip.Unmap()
}
func (m *Manager) Blocked(ip netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ip = ip.Unmap()
	if !ip.IsValid() || m.white.contains(ip) {
		return false
	}
	if b, ok := m.bans[ip.String()]; ok {
		if b.Expires.IsZero() || m.now().Before(b.Expires) {
			return true
		}
		delete(m.bans, ip.String())
		m.dirty = true
	}
	for _, f := range m.feeds {
		if f.source.Enabled && f.set.contains(ip) {
			return true
		}
	}
	return false
}
func (m *Manager) Observe(remote, path string, status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.cfg.AutoBan
	ip := Address(remote)
	if !a.Enabled || !ip.IsValid() || m.white.contains(ip) || (a.IgnorePrivate && !publicAddress(ip)) {
		return
	}
	match := false
	for _, code := range a.StatusCodes {
		if status == code {
			match = true
		}
	}
	if !match {
		return
	}
	for _, p := range a.IgnoredPaths {
		if path == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return
		}
	}
	now := m.now()
	if now.Sub(m.lastPrune) >= time.Second {
		m.prune(now)
	}
	key := ip.String()
	if _, ok := m.bans[key]; ok {
		return
	}
	times := m.counters[key]
	cut := now.Add(-time.Duration(a.WindowSeconds) * time.Second)
	i := 0
	for i < len(times) && !times[i].After(cut) {
		i++
	}
	m.events -= i
	if i > 0 {
		times = append([]time.Time(nil), times[i:]...)
		m.counters[key] = times
	}
	if len(times) == 0 && len(m.counters) >= MaxCounters {
		return
	}
	if m.events >= 50000 {
		return
	}
	times = append(times, now)
	m.events++
	if len(times) >= a.Threshold {
		if len(m.bans) < MaxBans {
			m.bans[key] = Ban{IP: key, Kind: "auto", Reason: "重复 HTTP 异常响应", Hits: len(times), Created: now, Expires: now.Add(time.Duration(a.BanSeconds) * time.Second)}
			m.dirty = true
		}
		m.events -= len(times)
		delete(m.counters, key)
	} else {
		m.counters[key] = times
	}
}
func (m *Manager) prune(now time.Time) {
	m.lastPrune = now
	for k, b := range m.bans {
		if !b.Expires.IsZero() && !now.Before(b.Expires) {
			delete(m.bans, k)
			m.dirty = true
		}
	}
	for k, v := range m.counters {
		if len(v) == 0 || now.Sub(v[len(v)-1]) >= time.Duration(m.cfg.AutoBan.WindowSeconds)*time.Second {
			m.events -= len(v)
			delete(m.counters, k)
		}
	}
}
func (m *Manager) Ban(ipText string, seconds int) error {
	ip, e := netip.ParseAddr(ipText)
	if e != nil || ip.Zone() != "" {
		return errors.New("请填写单个 IPv4 或 IPv6 地址")
	}
	if seconds < 0 || seconds > 2592000 {
		return errors.New("封禁时长需为 0（永久）或不超过 30 天")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune(m.now())
	key := ip.Unmap().String()
	if m.white.contains(ip) {
		return errors.New("此 IP 匹配白名单，请先修改白名单")
	}
	if _, ok := m.bans[key]; !ok && len(m.bans) >= MaxBans {
		return errors.New("封禁记录已达上限")
	}
	b := Ban{IP: key, Kind: "manual", Reason: "手动封禁", Created: m.now()}
	if seconds > 0 {
		b.Expires = b.Created.Add(time.Duration(seconds) * time.Second)
	}
	m.bans[key] = b
	m.dirty = true
	m.dropCounter(key)
	return m.saveLocked()
}
func (m *Manager) Unban(ip string, clearAuto bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if clearAuto {
		for k, b := range m.bans {
			if b.Kind == "auto" {
				delete(m.bans, k)
			}
		}
		m.counters = map[string][]time.Time{}
		m.events = 0
	} else {
		p, e := netip.ParseAddr(ip)
		if e != nil {
			return errors.New("IP 无效")
		}
		delete(m.bans, p.Unmap().String())
		m.dropCounter(p.Unmap().String())
	}
	m.dirty = true
	return m.saveLocked()
}
func (m *Manager) dropCounter(key string) { m.events -= len(m.counters[key]); delete(m.counters, key) }
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune(m.now())
	s := State{Bans: []Ban{}, Sources: []FeedState{}, PersistenceError: m.persistError}
	for _, b := range m.bans {
		s.Bans = append(s.Bans, b)
	}
	sort.Slice(s.Bans, func(i, j int) bool { return s.Bans[i].Created.After(s.Bans[j].Created) })
	for _, src := range m.cfg.Sources {
		f := m.feeds[src.ID]
		if f != nil {
			s.Sources = append(s.Sources, f.state())
		}
	}
	return s
}
func atomicWrite(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".access-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	e = f.Chmod(0600)
	if e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func (m *Manager) saveLocked() error {
	entries := []Ban{}
	for _, b := range m.bans {
		entries = append(entries, b)
	}
	data, _ := json.Marshal(entries)
	e := atomicWrite(filepath.Join(m.dir, "bans.json"), data)
	if e != nil {
		m.persistError = e.Error()
	} else {
		m.persistError = ""
		m.dirty = false
	}
	return e
}
func (m *Manager) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune(m.now())
	if m.dirty {
		return m.saveLocked()
	}
	return nil
}
