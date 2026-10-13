package app

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := newStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func quiet(string, string) {}
func TestStoreEncryption(t *testing.T) {
	s := testStore(t)
	c := s.snapshot()
	c.DNS = DNSAccount{AccessKeyID: "test-id", Secret: "private-test-secret"}
	if e := s.save(c); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(s.dir, "config.json"))
	if strings.Contains(string(b), "private-test-secret") {
		t.Fatal("plaintext secret on disk")
	}
	c = s.snapshot()
	c.DNS.Secret = ""
	if e := s.save(c); e != nil {
		t.Fatal(e)
	}
	again, e := newStore(s.dir)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := again.secret()
	if e != nil || secret != "private-test-secret" {
		t.Fatalf("reopen %q %v", secret, e)
	}
	os.Remove(filepath.Join(s.dir, "master.key"))
	if _, e = newStore(s.dir); e == nil {
		t.Fatal("missing key silently replaced")
	}
}
func TestValidation(t *testing.T) {
	base := Rule{ID: "one", Name: "test", Kind: "tcp", Listen: "0.0.0.0:18800", Target: "192.0.2.1:80", Enabled: true}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"duplicate", func(c *Config) { c.Rules = append(c.Rules, c.Rules[0]) }},
		{"admin collision", func(c *Config) { c.Rules[0].Listen = "0.0.0.0:17880" }},
		{"shell input", func(c *Config) { c.Rules[0].Listen = "0.0.0.0:18800; reboot" }},
		{"reserved firewall", func(c *Config) { c.Rules[0].Listen = "0.0.0.0:3964"; c.Rules[0].OpenFirewall = true }},
		{"loop", func(c *Config) { c.Rules[0].Target = "127.0.0.1:18800" }},
		{"web loop", func(c *Config) { c.Rules[0].Kind = "web"; c.Rules[0].Target = "http://127.0.0.1:18800" }},
		{"key traversal", func(c *Config) {
			c.Rules[0].Kind = "web"
			c.Rules[0].Target = "https://example.com"
			c.Rules[0].TLS = true
			c.Rules[0].Certificate = "../private"
		}},
		{"unsafe link", func(c *Config) { c.Bookmarks = []Bookmark{{ID: "link", URL: "javascript:alert(1)"}} }},
		{"bad blacklist", func(c *Config) { c.Blacklist = []string{"192.0.2.1\n-A INPUT -j ACCEPT"} }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{Rules: []Rule{base}}
			tt.mutate(&c)
			if validate(c, "127.0.0.1:17880") == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	if e := validate(Config{Rules: []Rule{base}}, "127.0.0.1:17880"); e != nil {
		t.Fatal(e)
	}
	c := Config{Blacklist: []string{"192.0.2.0/24"}, Whitelist: []string{"192.0.2.5"}}
	if blocked(net.ParseIP("192.0.2.5"), c) || !blocked(net.ParseIP("192.0.2.6"), c) || blocked(net.ParseIP("198.51.100.1"), c) {
		t.Fatal("CIDR exception mismatch")
	}
}
func TestFirewallScope(t *testing.T) {
	rules := []Rule{{Kind: "tcp", Listen: "0.0.0.0:18000", OpenFirewall: true}, {Kind: "udp", Listen: "[::1]:19000", OpenFirewall: true}}
	c := Config{Blacklist: []string{"192.0.2.0/24"}}
	v4 := buildFirewall(rules, c, false)
	v6 := buildFirewall(rules, c, true)
	if strings.Contains(v4, "-F INPUT") || !strings.Contains(v4, "-F LNEST_IN") || !strings.Contains(v4, "--dport 18000") || strings.Contains(v4, "19000") {
		t.Fatal(v4)
	}
	if strings.Contains(v6, "18000") || !strings.Contains(v6, "--dport 19000") {
		t.Fatal(v6)
	}
	c.Whitelist = []string{"192.0.2.1"}
	if strings.Contains(buildFirewall(rules, c, false), "-j DROP") {
		t.Fatal("kernel must not override app whitelist exceptions")
	}
	f := newFirewall(false)
	f.run = func(string, []string, string) (string, error) {
		t.Fatal("default firewall touched system")
		return "", nil
	}
	f.sync(rules, c)
	f.cleanup()
}
