package app

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockUPnP struct {
	mu       sync.Mutex
	maps     []UPnPMapping
	failPort int
	newOwner bool
	calls    []string
}

func fixtureUPnP(t *testing.T) (*mockUPnP, *httptest.Server) {
	t.Helper()
	mock := &mockUPnP{maps: []UPnPMapping{{Protocol: "TCP", ExternalPort: 45670, InternalIP: "192.168.10.2", InternalPort: 8080, Enabled: true, Description: "original & <entry>", LeaseSeconds: 600}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		if r.Method == "GET" {
			fmt.Fprint(w, `<root><device><deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/control</controlURL></service></serviceList></device></deviceList></device></root>`)
			return
		}
		mock.mu.Lock()
		defer mock.mu.Unlock()
		action := strings.Trim(strings.SplitN(r.Header.Get("SOAPAction"), "#", 2)[1], `"`)
		mock.calls = append(mock.calls, action)
		fields := map[string]string{}
		decoder := xml.NewDecoder(r.Body)
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Error(err)
				return
			}
			if e, ok := token.(xml.StartElement); ok && strings.HasPrefix(e.Name.Local, "New") {
				var value string
				decoder.DecodeElement(&value, &e)
				fields[e.Name.Local] = value
			}
		}
		code := 0
		result := map[string]string{}
		key := UPnPMapping{RemoteHost: fields["NewRemoteHost"], Protocol: fields["NewProtocol"]}
		fmt.Sscan(fields["NewExternalPort"], &key.ExternalPort)
		index := -1
		for i, m := range mock.maps {
			if m.ExternalPort == key.ExternalPort && m.Protocol == key.Protocol && m.RemoteHost == key.RemoteHost {
				index = i
				break
			}
		}
		switch action {
		case "GetGenericPortMappingEntry":
			var n int
			fmt.Sscan(fields["NewPortMappingIndex"], &n)
			if n >= len(mock.maps) {
				code = 713
			} else {
				result = upnpFixtureFields(mock.maps[n])
			}
		case "GetSpecificPortMappingEntry":
			if index < 0 {
				code = 714
			} else {
				result = upnpFixtureFields(mock.maps[index])
			}
		case "AddPortMapping":
			if key.ExternalPort == mock.failPort {
				code = 606
				break
			}
			m, err := upnpMappingFrom(fields)
			if err != nil {
				t.Error(err)
				code = 402
				break
			}
			if index >= 0 {
				mock.maps[index] = m
			} else {
				mock.maps = append(mock.maps, m)
			}
		case "DeletePortMapping":
			if index < 0 {
				code = 714
			} else {
				mock.maps = append(mock.maps[:index], mock.maps[index+1:]...)
				if mock.newOwner {
					other := key
					other.InternalIP = "192.168.10.99"
					other.InternalPort = 80
					other.Enabled = true
					mock.maps = append(mock.maps, other)
				}
			}
		default:
			t.Error(action)
			code = 401
		}
		if code != 0 {
			w.WriteHeader(500)
			fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError><errorCode>%d</errorCode><errorDescription>fixture error</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code)
			return
		}
		fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:%sResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">`, action)
		for k, v := range result {
			fmt.Fprintf(w, "<%s>%s</%s>", k, xmlText(v), k)
		}
		fmt.Fprintf(w, "</u:%sResponse></s:Body></s:Envelope>", action)
	}))
	t.Cleanup(server.Close)
	return mock, server
}
func upnpFixtureFields(m UPnPMapping) map[string]string {
	e := "0"
	if m.Enabled {
		e = "1"
	}
	return map[string]string{"NewRemoteHost": m.RemoteHost, "NewProtocol": m.Protocol, "NewExternalPort": fmt.Sprint(m.ExternalPort), "NewInternalClient": m.InternalIP, "NewInternalPort": fmt.Sprint(m.InternalPort), "NewEnabled": e, "NewPortMappingDescription": m.Description, "NewLeaseDuration": fmt.Sprint(m.LeaseSeconds)}
}
func TestUPnPDiscoveryAndMutation(t *testing.T) {
	for _, operation := range []string{"list", "add", "edit", "delete", "rollback", "concurrent", "conflict", "new-owner"} {
		t.Run(operation, func(t *testing.T) {
			mock, server := fixtureUPnP(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			service, err := discoverUPnP(ctx, UPnPConfig{DescriptionURL: server.URL + "/rootDesc.xml"}, upnpHTTPClient)
			if err != nil {
				t.Fatal(err)
			}
			before := mock.maps[0]
			after := before
			after.ExternalPort++
			after.Description = "new & entry"
			after.LeaseSeconds = 3600
			if operation == "list" {
				maps, truncated, err := service.list(ctx)
				if err != nil || truncated || len(maps) != 1 || maps[0].Description != before.Description {
					t.Fatal(maps, truncated, err)
				}
				return
			}
			if operation == "conflict" {
				after = before
				err = service.mutate(ctx, "add", UPnPMapping{}, after)
				if err == nil {
					t.Fatal("overwrote existing entry")
				}
				return
			}
			if operation == "rollback" || operation == "new-owner" {
				mock.failPort = after.ExternalPort
			}
			if operation == "new-owner" {
				mock.newOwner = true
			}
			if operation == "concurrent" {
				mock.maps[0].InternalPort = 9090
			}
			op := operation
			if op == "rollback" || op == "concurrent" || op == "new-owner" {
				op = "edit"
			}
			err = service.mutate(ctx, op, before, after)
			if operation == "rollback" {
				if err == nil || !strings.Contains(err.Error(), "已恢复") || len(mock.maps) != 1 || !sameUPnPMapping(mock.maps[0], before) {
					t.Fatal(mock.maps, err)
				}
				return
			}
			if operation == "new-owner" {
				if err == nil || len(mock.maps) != 1 || mock.maps[0].InternalIP != "192.168.10.99" {
					t.Fatal("overwrote concurrent owner", mock.maps, err)
				}
				return
			}
			if operation == "concurrent" {
				if err == nil || len(mock.calls) != 1 {
					t.Fatal("mutated changed mapping", mock.calls, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if op == "add" {
				want = 2
			}
			if op == "delete" {
				want = 0
			}
			if len(mock.maps) != want {
				t.Fatal(mock.maps)
			}
		})
	}
}
func TestUPnPEndpointAndPolicyValidation(t *testing.T) {
	for _, raw := range []string{"https://192.168.1.1/rootDesc.xml", "http://example.com/rootDesc.xml", "http://8.8.8.8/rootDesc.xml", "http://192.168.1.1/rootDesc.xml?token=x", "http://user:pass@192.168.1.1/rootDesc.xml"} {
		if _, err := upnpEndpoint(raw); err == nil {
			t.Fatal("accepted unsafe endpoint", raw)
		}
	}
	for _, address := range []string{"192.168.1.2", "192.168.1.0/24", "2C-F0-5D-E0-69-6D", "2CF0.5DE0.696D"} {
		if _, _, err := upnpBlockAddress(address); err != nil {
			t.Fatal(address, err)
		}
	}
	for _, address := range []string{"0.0.0.0/0", "8.8.8.8", "192.168.1.1/8", "FF:FF:FF:FF:FF:FF", "192.168.1.1; reboot"} {
		if _, _, err := upnpBlockAddress(address); err == nil {
			t.Fatal("unsafe block", address)
		}
	}
	c := UPnPConfig{Enabled: true, DescriptionURL: "http://192.168.1.1:5351/rootDesc.xml", Interface: "br-lan", LANZone: "lan", Blacklist: []UPnPBlock{{ID: "test", Name: "hello'\"; reboot", Address: "192.168.1.2", Enabled: true}, {ID: "mac", Address: "2C-F0-5D-E0-69-6D", Enabled: true}}}
	script, err := buildUPnPPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{"LNEST_UPNP", "src_mac=2C:F0:5D:E0:69:6D", "src_ip=192.168.1.2/32", "--dport 5351", "upnp-v1", "--test --noflush", "rollback_chain", "uci -c", "changes firewall", "flock -n"} {
		if !strings.Contains(script, must) {
			t.Fatal("missing safeguard", must)
		}
	}
	for _, bad := range []string{c.Blacklist[0].Name, "-F INPUT", "-F FORWARD", "/etc/init.d/firewall", "miniupnpd restart", "/etc/config/upnpd"} {
		if strings.Contains(script, bad) {
			t.Fatal("unscoped command", bad)
		}
	}
	macs := map[string]string{"192.168.1.3": "2C:F0:5D:E0:69:6D"}
	if !upnpBlockedMapping(c, UPnPMapping{InternalIP: "192.168.1.3"}, macs) || upnpBlockedMapping(c, UPnPMapping{InternalIP: "192.168.1.9"}, macs) {
		t.Fatal("bad device matching")
	}
}
func TestUPnPAPIGuardsAndPersistence(t *testing.T) {
	a := testApp(t)
	defer a.dns.close()
	cookie := signIn(t, a)
	for _, path := range []string{"/api/upnp/state", "/api/upnp/config", "/api/upnp/mapping", "/api/upnp/policy"} {
		method := "POST"
		if strings.HasSuffix(path, "state") {
			method = "GET"
		}
		if w := request(a, method, path, map[string]any{}, nil); w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/api/upnp/config", "/api/upnp/mapping", "/api/upnp/policy"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("missing CSRF accepted", path, w.Code)
		}
	}
	c := UPnPConfig{DescriptionURL: "http://192.168.1.1:5351/rootDesc.xml", Blacklist: []UPnPBlock{{ID: "mac", Address: "2C-F0-5D-E0-69-6D", Enabled: true}}}
	if w := request(a, "PUT", "/api/upnp/config", c, cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	before := a.store.snapshot()
	u := newUPnP(a.store)
	saved, _, _, err := u.snapshot()
	if err != "" || saved.Blacklist[0].Address != "2C:F0:5D:E0:69:6D" || saved.Enabled {
		t.Fatal(saved, err)
	}
	if a.store.snapshot().Schema != before.Schema {
		t.Fatal("changed core schema")
	}
	w := request(a, "GET", "/api/upnp/state", nil, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "192.168.1.1") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(a, "POST", "/api/upnp/mapping", map[string]any{}, cookie); w.Code != 409 {
		t.Fatal(w.Code)
	}
	file := filepath.Join(a.store.dir, "upnp", "config.json")
	b, _ := os.ReadFile(file)
	var decoded map[string]any
	if json.Unmarshal(b, &decoded) != nil || strings.Contains(string(b), "password") {
		t.Fatal("invalid/secrets in policy config")
	}
	a.upnp.op.Lock()
	w = request(a, "GET", "/api/upnp/state", nil, cookie)
	a.upnp.op.Unlock()
	if w.Code != 409 {
		t.Fatal("concurrent operation accepted", w.Code)
	}
}
func TestUPnPAPIConflictsWithLinkNest(t *testing.T) {
	a := testApp(t)
	defer a.dns.close()
	cookie := signIn(t, a)
	_, server := fixtureUPnP(t)
	c := UPnPConfig{Enabled: true, DescriptionURL: server.URL + "/rootDesc.xml"}
	if err := a.upnp.save(c, "", ""); err != nil {
		t.Fatal(err)
	}
	core := a.store.snapshot()
	core.Rules = []Rule{{ID: "owned", Name: "existing", Kind: "web", Listen: "0.0.0.0:45671", Network: "ipv4", Enabled: true}}
	a.store.save(core)
	m := UPnPMapping{Protocol: "TCP", ExternalPort: 45671, InternalIP: "192.168.10.2", InternalPort: 80, Enabled: true}
	w := request(a, "POST", "/api/upnp/mapping", map[string]any{"operation": "add", "after": m}, cookie)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestUPnPLiveReadOnly(t *testing.T) {
	endpoint := os.Getenv("LINKNEST_UPNP_LIVE_URL")
	if endpoint == "" {
		t.Skip("opt-in read-only interface fixture")
	}
	c := UPnPConfig{DescriptionURL: endpoint, Interface: os.Getenv("LINKNEST_UPNP_LIVE_INTERFACE")}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := discoverUPnP(ctx, c, upnpHTTPClient)
	if err != nil {
		t.Fatal(err)
	}
	maps, truncated, err := s.list(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Read-only discovery/list: %d mappings, truncated=%v", len(maps), truncated)
}

// Explicit opt-in only. Caller must first verify the two target ports are not
// listening and the external ports have no unrelated router/NAT owner.
func TestUPnPLiveLifecycle(t *testing.T) {
	if os.Getenv("LINKNEST_UPNP_LIVE_MUTATE") != "confirmed" {
		t.Skip("requires explicit temporary mapping authorization")
	}
	c := UPnPConfig{DescriptionURL: os.Getenv("LINKNEST_UPNP_LIVE_URL"), Interface: os.Getenv("LINKNEST_UPNP_LIVE_INTERFACE")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := discoverUPnP(ctx, c, upnpHTTPClient)
	if err != nil {
		t.Fatal(err)
	}
	marker := "LinkNest temporary QA " + token(6)
	first := UPnPMapping{Protocol: "TCP", ExternalPort: 64791, InternalIP: os.Getenv("LINKNEST_UPNP_LIVE_TARGET"), InternalPort: 65431, Enabled: true, Description: marker, LeaseSeconds: 60}
	second := first
	second.Protocol = "UDP"
	second.ExternalPort = 64792
	second.InternalPort = 65432
	if snapshot, err := command("iptables", []string{"-t", "nat", "-S"}, ""); err != nil {
		t.Fatal(err)
	} else {
		rules := []Rule{{ID: "one", Enabled: true, Kind: "tcpudp", Network: "ipv4", Listen: "0.0.0.0:64791"}, {ID: "two", Enabled: true, Kind: "tcpudp", Network: "ipv4", Listen: "0.0.0.0:64792"}}
		if conflicts := natConflicts(snapshot, rules, false); len(conflicts) != 0 {
			t.Fatal("temporary ports already used by NAT", conflicts)
		}
	}
	for _, m := range []UPnPMapping{first, second} {
		if _, err := s.get(ctx, m); err == nil {
			t.Fatal("test port already mapped")
		} else {
			var soap *upnpSOAPError
			if !errors.As(err, &soap) || soap.Code != 714 {
				t.Fatal(err)
			}
		}
	}
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 8*time.Second)
		defer stop()
		for _, m := range []UPnPMapping{first, second} {
			current, err := s.get(cleanupCtx, m)
			if err == nil && current.Description == marker {
				if err = s.remove(cleanupCtx, current); err != nil {
					t.Error("temporary mapping cleanup failed", err)
				}
			}
		}
	}()
	if err = s.mutate(ctx, "add", UPnPMapping{}, first); err != nil {
		t.Fatal("temporary add", err)
	}
	if err = s.mutate(ctx, "edit", first, second); err != nil {
		t.Fatal("temporary edit", err)
	}
	if err = s.mutate(ctx, "delete", second, UPnPMapping{}); err != nil {
		t.Fatal("temporary delete", err)
	}
	for _, m := range []UPnPMapping{first, second} {
		if _, err := s.get(ctx, m); err == nil {
			t.Fatal("temporary mapping still present")
		}
	}
	t.Log("Temporary TCP add → UDP edit → delete verified, both QA mappings absent")
}
