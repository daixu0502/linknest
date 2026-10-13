package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDNSDeleteExactLineAndAmbiguity(t *testing.T) {
	for _, scenario := range []string{"one", "missing", "duplicate", "denied", "auto"} {
		t.Run(scenario, func(t *testing.T) {
			deletes := 0
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.ParseForm()
				switch r.Form.Get("Action") {
				case "DescribeDomains":
					fmt.Fprint(w, `{"TotalCount":1,"Domains":{"Domain":[{"DomainName":"example.com"}]}}`)
				case "DescribeDomainRecords":
					if r.Form.Get("RRKeyWord") != "home" || r.Form.Get("TypeKeyWord") != "A" || r.Form.Get("DomainName") != "example.com" {
						t.Error(r.Form)
					}
					items := `{"RecordId":"other-line","RR":"home","Type":"A","Line":"telecom"}`
					if scenario != "missing" {
						items += `,{"RecordId":"selected","RR":"home","Type":"A","Line":"default"}`
					}
					if scenario == "duplicate" {
						items += `,{"RecordId":"ambiguous","RR":"home","Type":"A","Line":"default"}`
					}
					fmt.Fprintf(w, `{"TotalCount":3,"DomainRecords":{"Record":[%s]}}`, items)
				case "DeleteDomainRecord":
					deletes++
					if r.Form.Get("RecordId") != "selected" {
						t.Error("wrong remote record deleted")
					}
					if scenario == "denied" {
						fmt.Fprint(w, `{"Code":"Forbidden","Message":"RAM denied"}`)
					} else {
						fmt.Fprint(w, `{"RecordId":"selected"}`)
					}
				default:
					t.Error("unexpected write", r.Form.Get("Action"))
				}
			}))
			defer mock.Close()
			rec := DDNSRecord{Domain: "home.example.com", Zone: "example.com", Type: "A", Line: "default"}
			if scenario == "auto" {
				rec.Zone = ""
			}
			ok, err := (AliDNS{ID: "fake", Secret: "fake", Endpoint: mock.URL, Client: mock.Client()}).deleteRecord(context.Background(), rec)
			wantError := scenario == "duplicate" || scenario == "denied"
			if (err != nil) != wantError || ok != (scenario == "one" || scenario == "auto") {
				t.Fatal(ok, err)
			}
			wantDeletes := 1
			if scenario == "missing" || scenario == "duplicate" {
				wantDeletes = 0
			}
			if deletes != wantDeletes {
				t.Fatal(deletes)
			}
		})
	}
}

func TestDNSDeleteAPIKeepsConfigOnFailureAndExcludesUpdates(t *testing.T) {
	for _, mode := range []string{"local", "remote", "failed", "busy", "reserved", "shared"} {
		t.Run(mode, func(t *testing.T) {
			a := testApp(t)
			defer a.dns.close()
			cookie := signIn(t, a)
			c := a.store.snapshot()
			c.DNS = DNSAccount{AccessKeyID: "fake", Secret: "fake"}
			rec := DDNSRecord{ID: "record", Domain: "home.example.com", Zone: "example.com", Type: "A", Line: "default", Value: "192.0.2.2"}
			c.DDNS = []DDNSRule{{ID: "task", Name: "task", Records: []DDNSRecord{rec}}}
			if mode == "shared" {
				other := rec
				other.ID = "other"
				c.DDNS[0].Records = append(c.DDNS[0].Records, other)
			}
			if err := a.store.save(c); err != nil {
				t.Fatal(err)
			}
			writes := 0
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.ParseForm()
				if r.Form.Get("Action") == "DescribeDomainRecords" {
					fmt.Fprint(w, `{"TotalCount":1,"DomainRecords":{"Record":[{"RecordId":"r1","RR":"home","Type":"A","Line":"default"}]}}`)
					return
				}
				writes++
				if mode == "failed" {
					fmt.Fprint(w, `{"Code":"Forbidden","Message":"denied"}`)
				} else {
					fmt.Fprint(w, `{"RecordId":"r1"}`)
				}
			}))
			defer mock.Close()
			a.dns.client = func(acc DNSAccount) AliDNS {
				return AliDNS{ID: acc.AccessKeyID, Secret: acc.Secret, Endpoint: mock.URL, Client: mock.Client()}
			}
			if mode == "busy" {
				a.dns.running["task"] = true
			}
			if mode == "reserved" {
				if !a.dns.reserveDelete("task") || a.dns.start(c.DDNS[0]) {
					t.Fatal("deletion raced with updater")
				}
			}
			payload := map[string]any{"id": "task", "recordId": "record", "deleteRemote": mode != "local"}
			if w := request(a, "POST", "/api/ddns/record/delete", payload, nil); w.Code != 401 {
				t.Fatal("missing auth accepted", w.Code)
			}
			w := request(a, "POST", "/api/ddns/record/delete", payload, cookie)
			success := mode == "local" || mode == "remote"
			if (w.Code == 200) != success {
				t.Fatal(w.Code, w.Body.String())
			}
			remaining := len(a.store.snapshot().DDNS[0].Records)
			if success && remaining != 0 || !success && remaining == 0 {
				t.Fatal("lost configuration", remaining)
			}
			if mode == "local" && writes != 0 || mode == "remote" && writes != 1 {
				t.Fatal(writes)
			}
			a.dns.releaseDelete("task")
		})
	}
}

func TestKernelRulesAreScopedAndDoNotWeakenFirewall(t *testing.T) {
	r := Rule{ID: "rdp", Kind: "tcpudp", Network: "ipv4", Listen: "0.0.0.0:39642", Target: "192.0.2.20:3389", ForwardMode: "kernel", OpenFirewall: true}
	if err := validateKernelRule(r); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Rule){func(r *Rule) { r.Network = "dual" }, func(r *Rule) { r.Target = "localhost:3389" }, func(r *Rule) { r.Kind = "web" }, func(r *Rule) { r.Target = "127.0.0.1:3389" }} {
		bad := r
		mutate(&bad)
		if validateKernelRule(bad) == nil {
			t.Fatal("unsafe kernel rule accepted", bad)
		}
	}
	c := Config{Whitelist: []string{"192.0.2.10/32"}, Blacklist: []string{"192.0.2.0/24", "2001:db8::/32"}}
	filter, nat := buildKernel([]Rule{r}, c)
	for _, proto := range []string{"tcp", "udp"} {
		if !strings.Contains(nat, "! -i lo -p "+proto+" --dport 39642 -m addrtype --dst-type LOCAL") {
			t.Fatal(nat)
		}
		if !strings.Contains(filter, "-p "+proto+" -d 192.0.2.20 --dport 3389 -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdstport 39642") {
			t.Fatal(filter)
		}
	}
	if strings.Index(filter, "-s 192.0.2.10/32") > strings.Index(filter, "-s 192.0.2.0/24") {
		t.Fatal("whitelist after blacklist")
	}
	if strings.Contains(filter, "2001:db8") || strings.Contains(nat, "-F PREROUTING") || strings.Contains(filter, "-F FORWARD") || strings.Contains(filter, "-A FORWARD") {
		t.Fatal("unscoped changes")
	}
	r.OpenFirewall = false
	filter, _ = buildKernel([]Rule{r}, c)
	if strings.Contains(filter, "-j ACCEPT") {
		t.Fatal("bypassed router policy", filter)
	}
	if strings.Contains(buildFirewall([]Rule{r}, c, false), "--dport 39642") {
		t.Fatal("kernel rules leaked into INPUT")
	}
	r.Listen = "192.0.2.1:39642"
	filter, nat = buildKernel([]Rule{r}, c)
	if !strings.Contains(filter, "--ctorigdst 192.0.2.1") || !strings.Contains(nat, "-d 192.0.2.1 -j DNAT") {
		t.Fatal("lost listener scope")
	}
}

func TestPacketACLDoesNotCloneConfigAndChangesImmediately(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 100; i++ {
		s.cfg.Bookmarks = append(s.cfg.Bookmarks, Bookmark{ID: fmt.Sprint(i), Name: strings.Repeat("x", 100)})
	}
	ip := net.ParseIP("192.0.2.4")
	if n := testing.AllocsPerRun(100, func() { s.blockedIP(ip) }); n != 0 {
		t.Fatal("config allocation per packet", n)
	}
	c := s.snapshot()
	c.Blacklist = []string{"192.0.2.4"}
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	if !s.blockedIP(ip) {
		t.Fatal("old ACL")
	}
	c.Whitelist = []string{"192.0.2.4"}
	s.save(c)
	if s.blockedIP(ip) {
		t.Fatal("whitelist ignored")
	}
}

func BenchmarkPacketACL(b *testing.B) {
	s := &Store{cfg: Config{Blacklist: []string{"198.51.100.0/24"}}}
	for i := 0; i < 100; i++ {
		s.cfg.Bookmarks = append(s.cfg.Bookmarks, Bookmark{ID: fmt.Sprint(i), Name: strings.Repeat("x", 100)})
	}
	ip := net.ParseIP("192.0.2.4")
	b.Run("previous-config-copy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			blocked(ip, s.snapshot())
		}
	})
	b.Run("packet-only", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.blockedIP(ip)
		}
	})
}
