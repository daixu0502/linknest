package app

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
)

const routerNATFixture = `-P PREROUTING ACCEPT
-N MINIUPNPD
-N wan
-N unattached
-A PREROUTING -j LNEST_DNAT
-A PREROUTING -i pppoe-wan -j wan
-A wan -j MINIUPNPD
-A MINIUPNPD -p tcp -m tcp --dport 6881 -j DNAT --to-destination 10.31.0.2:6881
-A MINIUPNPD -p udp -m udp --dport 6881 -j DNAT --to-destination 10.31.0.2:6881
-A wan -p tcp -m multiport --dports 1000:2000,8443 -j REDIRECT --to-ports 443
-A LNEST_DNAT -p tcp --dport 39642 -j DNAT --to-destination 10.31.0.2:3389
-A unattached -p tcp --dport 9001 -j DNAT --to-destination 10.31.0.2:9001
-A OUTPUT -p tcp --dport 9002 -j REDIRECT --to-ports 443
-A wan -p tcp --dport 9003 -m comment --comment "example -j DNAT --dport 9004" -j RETURN
`

func TestRouterNATConflicts(t *testing.T) {
	for _, tc := range []struct {
		port, kind, network, host string
		want                      bool
	}{
		{"6881", "tcpudp", "dual", "[::]", true},
		{"6881", "udp", "ipv4", "0.0.0.0", true},
		{"6881", "tcp", "ipv6", "[::]", false},
		{"8443", "tcp", "ipv4", "0.0.0.0", true},
		{"1500", "tcp", "ipv4", "0.0.0.0", true},
		{"1500", "udp", "ipv4", "0.0.0.0", false},
		{"39642", "tcp", "ipv4", "0.0.0.0", false},
		{"9001", "tcp", "ipv4", "0.0.0.0", false},
		{"9002", "tcp", "ipv4", "0.0.0.0", false},
		{"9004", "tcp", "ipv4", "0.0.0.0", false},
	} {
		r := Rule{ID: "r", Enabled: true, Kind: tc.kind, Network: tc.network, Listen: tc.host + ":" + tc.port}
		got := natConflicts(routerNATFixture, []Rule{r}, false)[r.ID]
		if (got != nil) != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
		if tc.want && tc.port == "6881" && !strings.Contains(got.Error(), "UPnP / PCP") {
			t.Fatal(got)
		}
	}
}

func TestRouterNATScopeAndCycles(t *testing.T) {
	for _, tc := range []struct {
		rule, host, proto string
		want              bool
	}{
		{`-d 192.0.2.0/24 -p tcp --dport 6881`, "192.0.2.1", "tcp", true},
		{`-d 192.0.2.0/24 -p tcp --dport 6881`, "198.51.100.1", "tcp", false},
		{`! -d 192.0.2.0/24 -p tcp --dport 6881`, "192.0.2.1", "tcp", false},
		{`! -d 192.0.2.0/24 -p tcp --dport 6881`, "0.0.0.0", "tcp", true},
		{`! -p tcp --dport 6881`, "0.0.0.0", "udp", true},
		{`-p tcp ! --dport 6881`, "0.0.0.0", "tcp", false},
		{`-i lo -p tcp --dport 6881`, "0.0.0.0", "tcp", false},
	} {
		s := `-A PREROUTING -j wan
-A wan -j PREROUTING
-A wan ` + tc.rule + ` -j DNAT --to-destination 10.31.0.2:6881`
		r := Rule{ID: "r", Kind: tc.proto, Network: "ipv4", Listen: tc.host + ":6881"}
		if got := natConflicts(s, []Rule{r}, false)[r.ID]; (got != nil) != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
	for _, s := range []string{
		"-A PREROUTING -p udp -j wan\n-A wan -p tcp --dport 6881 -j REDIRECT --to-ports 80",
		"-A PREROUTING -d 192.0.2.0/24 -j wan\n-A wan -d 198.51.100.0/24 -j DNAT --to-destination 10.31.0.2:6881",
	} {
		if len(natConflicts(s, []Rule{{ID: "r", Kind: "tcp", Network: "ipv4", Listen: "0.0.0.0:6881"}}, false)) != 0 {
			t.Fatal("disjoint ingress path matched")
		}
	}
	v6 := "-A PREROUTING -d 2001:db8::/32 -p tcp --dport 6881 -j DNAT --to-destination [2001:db8::2]:6881"
	if len(natConflicts(v6, []Rule{{ID: "r", Kind: "tcp", Network: "ipv6", Listen: "[::]:6881"}}, true)) != 1 {
		t.Fatal("lost IPv6 mapping")
	}
}

func TestNATWordsRespectQuotedComments(t *testing.T) {
	w := natWords(`-A PREROUTING -m comment --comment "spaces \"quote\" -j DNAT" -j RETURN`)
	if len(w) != 8 || w[5] != `spaces "quote" -j DNAT` || w[7] != "RETURN" {
		t.Fatal(w)
	}
}

func TestForwardConflictSnapshots(t *testing.T) {
	f := newFirewall(true)
	calls := 0
	f.run = func(bin string, args []string, input string) (string, error) {
		calls++
		if !strings.Contains(strings.Join(args, " "), "-t nat -S") || input != "" {
			t.Fatal(args)
		}
		return routerNATFixture, nil
	}
	rules := []Rule{{ID: "one", Enabled: true, Kind: "tcp", Network: "ipv4", Listen: "0.0.0.0:6881"}, {ID: "two", Enabled: true, Kind: "tcp", Network: "ipv4", Listen: "0.0.0.0:39642"}}
	got := f.forwardConflicts(rules)
	if calls == 0 {
		t.Skip("runtime check requires Linux")
	}
	if calls != 1 || got["one"] == nil || got["two"] != nil {
		t.Fatal(calls, got)
	}
	f.run = func(string, []string, string) (string, error) { return "", errors.New("permission denied") }
	if len(f.forwardConflicts(rules)) != 2 {
		t.Fatal("failed scan was presented as successful")
	}
}

func TestEngineNATConflictLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux NAT inspection")
	}
	s := testStore(t)
	f := newFirewall(true)
	addr := freePort(t)
	_, port, _ := hostPort(addr)
	snapshot := fmt.Sprintf("-A PREROUTING -j MINIUPNPD\n-A MINIUPNPD -p tcp --dport %d -j DNAT --to-destination 192.0.2.2:80", port)
	f.run = func(bin string, args []string, input string) (string, error) {
		if strings.Join(args, " ") == "-w 3 -t nat -S" {
			return snapshot, nil
		}
		return "", errors.New("fixture: no host mutations")
	}
	e := newEngine(s, quiet, f)
	defer e.close()
	c := s.snapshot()
	r := Rule{ID: "forward", Name: "forward", Kind: "tcp", Network: "ipv4", Listen: addr, Target: "192.0.2.2:80", Enabled: true}
	c.Rules = []Rule{r}
	e.apply(c)
	if st := e.statuses(); len(st) != 1 || st[0].State != "error" || !strings.Contains(st[0].Message, "UPnP") {
		t.Fatal(st)
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal("conflicting listener still running", err)
	}
	ln.Close()
	snapshot = "-P PREROUTING ACCEPT\n"
	e.apply(c)
	if st := e.statuses(); st[0].State != "running" {
		t.Fatal("did not recover", st)
	}
	snapshot = fmt.Sprintf("-A PREROUTING -p tcp --dport %d -j REDIRECT --to-ports 80", port)
	e.apply(c)
	if st := e.statuses(); st[0].State != "error" {
		t.Fatal("new mapping not detected", st)
	}
	ln, err = net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal("listener not withdrawn", err)
	}
	ln.Close()
}

func TestKernelListenerProtocolDiagnostics(t *testing.T) {
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := Rule{Kind: "tcpudp", Network: "ipv4", ForwardMode: "kernel", Listen: ln.Addr().String(), Target: "192.0.2.20:3389"}
	if err := kernelRuleReady(r); err == nil || !strings.Contains(err.Error(), "TCP") {
		t.Fatal(err)
	}
	ln.Close()
	udp, err := net.ListenPacket("udp4", r.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := kernelRuleReady(r); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Fatal(err)
	}
	udp.Close()
	if err := kernelRuleReady(r); err != nil {
		t.Fatal("stale occupied state", err)
	}
}
