package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testManager(t *testing.T) (*Manager, *time.Time) {
	t.Helper()
	now := time.Now().UTC()
	m := New(t.TempDir())
	m.now = func() time.Time { return now }
	c := DefaultConfig()
	c.AutoBan.Enabled = true
	c.AutoBan.Threshold = 3
	c.AutoBan.BanSeconds = 60
	m.Configure(c, nil)
	return m, &now
}
func TestAutoBanWindowExpiryAndPersistence(t *testing.T) {
	m, now := testManager(t)
	ip := netip.MustParseAddr("8.8.8.8")
	m.Observe("8.8.8.8:1234", "/lost", 404)
	m.Observe("8.8.8.8:1234", "/lost", 200)
	m.Observe("8.8.8.8:1234", "/favicon.ico", 404)
	*now = now.Add(61 * time.Second)
	m.Observe("8.8.8.8:1234", "/lost", 404)
	m.Observe("8.8.8.8:1234", "/lost", 404)
	if m.Blocked(ip) {
		t.Fatal("expired events counted")
	}
	m.Observe("8.8.8.8:1234", "/lost", 404)
	if !m.Blocked(ip) {
		t.Fatal("threshold not enforced")
	}
	if e := m.Flush(); e != nil {
		t.Fatal(e)
	}
	n := New(m.dir)
	n.now = m.now
	if !n.Blocked(ip) {
		t.Fatal("restart lost ban")
	}
	*now = now.Add(61 * time.Second)
	if n.Blocked(ip) {
		t.Fatal("ban extended on restart")
	}
}
func TestPrivateWhitelistIPv6AndClear(t *testing.T) {
	m, _ := testManager(t)
	c := m.cfg
	m.Configure(c, []string{"8.8.8.0/24"})
	for i := 0; i < 10; i++ {
		for _, remote := range []string{"8.8.8.8:80", "192.168.1.2:80", "[::ffff:8.8.8.8]:80"} {
			m.Observe(remote, "/x", 404)
		}
	}
	if len(m.State().Bans) != 0 {
		t.Fatal("private or white counted")
	}
	remote := "[2606:4700:4700::1111]:80"
	for i := 0; i < 3; i++ {
		m.Observe(remote, "/x", 404)
	}
	if !m.Blocked(Address(remote)) {
		t.Fatal("IPv6 not banned")
	}
	if e := m.Ban("9.9.9.9", 0); e != nil {
		t.Fatal(e)
	}
	if e := m.Unban("", true); e != nil {
		t.Fatal(e)
	}
	if m.Blocked(Address(remote)) || !m.Blocked(Address("9.9.9.9")) {
		t.Fatal("clear-auto removed manual ban or left automatic")
	}
	if e := m.Unban("9.9.9.9", false); e != nil || m.Blocked(Address("9.9.9.9")) {
		t.Fatal("unban failed")
	}
}
func TestFeedParsingAndURLSafety(t *testing.T) {
	for _, tc := range []struct {
		format, data string
		valid        bool
	}{
		{"plain", "# date / copyright\n1.2.3.4\n1.2.3.0/24 # note\n1.2.3.4\n2001:db8::/32", true},
		{"spamhaus", "{\"cidr\":\"1.2.3.0/24\",\"sblid\":\"SBL1\"}\n{\"type\":\"metadata\",\"copyright\":\"Spamhaus Project\"}", true},
		{"plain", "<html>Denied</html>", false}, {"plain", "# empty", false}, {"plain", "1.2.3.4\ngarbage", false}, {"spamhaus", "{}", false},
	} {
		values, e := Parse([]byte(tc.data), tc.format)
		if (e == nil) != tc.valid {
			t.Fatalf("%q: %v", tc.data, e)
		}
		if tc.valid && len(values) == 0 {
			t.Fatal("no values")
		}
	}
	for _, url := range []string{"http://example.com/list", "https://127.0.0.1/list", "https://[::ffff:127.0.0.1]/list", "https://10.0.0.1/list", "https://example.com:8443/list", "https://example.com/list?secret=x", "https://u:p@example.com/list"} {
		if ValidateURL(url) == nil {
			t.Fatal("unsafe URL accepted", url)
		}
	}
	for _, ip := range []string{"169.254.169.254", "100.100.100.200", "198.18.1.1", "::1", "fc00::1", "64:ff9b::a00:1"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Fatal("unsafe IP", ip)
		}
	}
	if e := ValidateURL("https://example.com/list.txt"); e != nil {
		t.Fatal(e)
	}
	client := secureClient()
	defer client.CloseIdleConnections()
	r, _ := http.NewRequest("GET", "https://localhost/list", nil)
	if _, e := client.Do(r); e == nil {
		t.Fatal("DNS localhost SSRF allowed")
	}
}
func TestFeedIndependentCacheCooldownAndFailure(t *testing.T) {
	m, now := testManager(t)
	c := m.cfg
	c.Sources = []Source{{ID: "one", Name: "one", URL: "https://example.com/one", Format: "plain", Enabled: true, IntervalHours: 1}, {ID: "two", Name: "two", URL: "https://example.com/two", Format: "plain", Enabled: true, IntervalHours: 1}}
	m.Configure(c, nil)
	m.fetch = func(ctx context.Context, s Source) ([]byte, error) {
		if s.ID == "two" {
			return nil, errors.New("HTTP 503")
		}
		return []byte("1.2.3.0/24\n"), nil
	}
	if e := m.Update(context.Background(), "one"); e != nil {
		t.Fatal(e)
	}
	if !m.Blocked(Address("1.2.3.4")) {
		t.Fatal("feed not applied")
	}
	if e := m.Update(context.Background(), "one"); e == nil {
		t.Fatal("cooldown bypass")
	}
	if e := m.Update(context.Background(), "two"); e == nil {
		t.Fatal("failed source accepted")
	}
	if !m.Blocked(Address("1.2.3.4")) {
		t.Fatal("independent source was cleared")
	}
	n := New(m.dir)
	n.now = m.now
	n.Configure(c, nil)
	if !n.Blocked(Address("1.2.3.4")) {
		t.Fatal("cache not loaded")
	}
	if e := n.Update(context.Background(), "one"); e == nil {
		t.Fatal("restart bypasses cooldown")
	}
	*now = now.Add(time.Hour)
	m.fetch = func(context.Context, Source) ([]byte, error) { return []byte("<html>err</html>"), nil }
	if e := m.Update(context.Background(), "one"); e == nil {
		t.Fatal("bad feed accepted")
	}
	if !m.Blocked(Address("1.2.3.4")) {
		t.Fatal("failure destroyed old feed")
	}
	c.Sources[0].Enabled = false
	m.Configure(c, nil)
	if m.Blocked(Address("1.2.3.4")) {
		t.Fatal("disabled source still blocks")
	}
	c.Sources = nil
	m.Configure(c, nil)
	if _, e := os.Stat(filepath.Join(m.dir, "subscriptions", "one.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("deleted source cache not cleaned")
	}
}
func TestSourceEditDoesNotReuseOldList(t *testing.T) {
	m, _ := testManager(t)
	c := m.cfg
	c.Sources = []Source{{ID: "one", Name: "one", URL: "https://example.com/one", Format: "plain", Enabled: true, IntervalHours: 1}}
	m.Configure(c, nil)
	m.fetch = func(context.Context, Source) ([]byte, error) { return []byte("1.2.3.4"), nil }
	if e := m.Update(context.Background(), "one"); e != nil {
		t.Fatal(e)
	}
	c.Sources[0].URL = "https://example.com/new"
	m.Configure(c, nil)
	if m.Blocked(Address("1.2.3.4")) {
		t.Fatal("URL edit reused stale feed")
	}
}
func TestResponseInformationalAndStreaming(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &Response{ResponseWriter: rec}
	w.WriteHeader(103)
	if w.Status != 0 {
		t.Fatal("1xx recorded as final")
	}
	w.WriteHeader(404)
	if w.Status != 404 {
		t.Fatal("404 not recorded")
	}
	rec = httptest.NewRecorder()
	w = &Response{ResponseWriter: rec}
	if e := http.NewResponseController(w).Flush(); e != nil || !rec.Flushed || w.Status != 200 {
		t.Fatal("flush broken", e)
	}
}
