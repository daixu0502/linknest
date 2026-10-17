package app

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestUPnPPortsNativeDryRun(t *testing.T) {
	if os.Getenv("LINKNEST_UPNP_PORTS_DRY_RUN") != "1" {
		t.Skip("opt-in staged UCI validation only; no native files or services changed")
	}
	script, err := buildUPnPPortsScript([]int{64789, 64790})
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, ok := strings.Cut(script, "newsum=$(md5sum")
	if !ok || strings.Contains(prefix, "changed=1") {
		t.Fatal("unsafe dry-run boundary")
	}
	// Verify the materialized file through the stock renderer, not the staged
	// UCI view (which can conceal an unmerged custom delta).
	render := `(
 set +eu
 . /lib/functions.sh
 . /etc/init.d/miniupnpd
 UCI_CONFIG_DIR="$work/verify"
 config_load upnpd || exit 1
 tmpconf="$work/native-rendered"
 : >"$tmpconf"
 config_foreach conf_rule_add perm_rule "$tmpconf"
)
sed -n '/^allow /p;/^deny /p' "$work/native-rendered" | head -n 2 >"$work/native-first"
cmp -s "$work/expected" "$work/native-first" || { echo '原厂未读取物化保护规则' >&2; exit 1; }
`
	cmd := exec.Command("sh", "-c", prefix+render+"\necho LINKNEST_PORTS_DRY_RUN_OK\n")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "LINKNEST_PORTS_DRY_RUN_OK") {
		t.Fatalf("%v %s", err, out)
	}
	t.Log("Stock UCI section creation, ownership and reorder passed without writes to original files or service restart")
}

func TestUPnPProtectedForwardPorts(t *testing.T) {
	rules := []Rule{
		{Kind: "tcp", Enabled: true, Network: "ipv4", Listen: "0.0.0.0:6082"},
		{Kind: "udp", Enabled: true, Network: "dual", Listen: "[::]:6881"},
		{Kind: "tcpudp", Enabled: true, Network: "ipv4", Listen: "10.31.0.1:6082"},
		{Kind: "tcp", Enabled: true, Network: "ipv6", Listen: "[::]:8000"},
		{Kind: "web", Enabled: true, Network: "ipv4", Listen: "0.0.0.0:9000"},
		{Kind: "tcp", Enabled: false, Network: "ipv4", Listen: "0.0.0.0:7000"},
	}
	ports := upnpForwardPorts(rules)
	if !reflect.DeepEqual(ports, []int{6082, 6881}) {
		t.Fatal(ports)
	}
	maps := []UPnPMapping{{ExternalPort: 6082, Protocol: "UDP"}, {ExternalPort: 6881, Protocol: "TCP"}, {ExternalPort: 1234, Protocol: "TCP"}}
	if len(upnpPortConflicts(ports, maps)) != 2 {
		t.Fatal("stock permissions must reserve both protocols")
	}
	for _, ports := range [][]int{{0}, {-1}, {65536}, {1, 1}, {2, 1}} {
		if _, err := buildUPnPPortsScript(ports); err == nil {
			t.Fatal("invalid port accepted", ports)
		}
	}
}

func TestUPnPPortsAPIGuards(t *testing.T) {
	a := testApp(t)
	defer a.dns.close()
	cookie := signIn(t, a)
	if w := request(a, "POST", "/api/upnp/ports", map[string]any{}, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", "/api/upnp/ports", strings.NewReader(`{}`))
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	_, server := fixtureUPnP(t)
	c := UPnPConfig{Enabled: true, DescriptionURL: server.URL + "/rootDesc.xml"}
	if err := a.upnp.save(c, "", ""); err != nil {
		t.Fatal(err)
	}
	if w := request(a, "POST", "/api/upnp/ports", map[string]any{"enabled": true, "adminPassword": "wrong"}, cookie); w.Code != 403 {
		t.Fatal("invalid proof accepted", w.Code, w.Body.String())
	}
	c.PortProtection, c.ProtectedPorts = true, []int{45670}
	if w := request(a, "PUT", "/api/upnp/config", c, cookie); w.Code != 400 {
		t.Fatal("unprivileged config changed protected ports", w.Code)
	}
	if err := a.upnp.save(c, "", ""); err != nil {
		t.Fatal(err)
	}
	// Reject even the other protocol on a recently protected stock port.
	m := UPnPMapping{Protocol: "UDP", ExternalPort: 45670, InternalIP: "192.168.10.2", InternalPort: 8000, Enabled: true}
	if w := request(a, "POST", "/api/upnp/mapping", map[string]any{"operation": "add", "after": m}, cookie); w.Code != 409 {
		t.Fatal("reserved port accepted", w.Code, w.Body.String())
	}
	core := a.store.snapshot()
	core.Rules = []Rule{{ID: "reserved", Name: "reserved", Enabled: true, Kind: "tcp", Network: "ipv4", Listen: "0.0.0.0:45670"}}
	core.SSHHosts = []SSHHost{{ID: "router", Username: "root", Address: server.Listener.Addr().String(), Fingerprint: "SHA256:test-only"}}
	a.store.save(core)
	// Existing conflict is returned before any SSH connection or mutation.
	if w := request(a, "POST", "/api/upnp/ports", map[string]any{"enabled": true, "hostId": "router", "adminPassword": "test-password-12345", "password": "unused"}, cookie); w.Code != 409 || !strings.Contains(w.Body.String(), "45670") {
		t.Fatal(w.Code, w.Body.String())
	}
	c.ProtectedPorts = []int{1234}
	a.upnp.save(c, "", "")
	status := a.upnpPortsStatus(core.Rules)
	if status["pending"] != true {
		t.Fatal("stale installed ports claimed synchronized")
	}
	loaded := newUPnP(a.store)
	saved, _, _, _ := loaded.snapshot()
	if !saved.PortProtection || !reflect.DeepEqual(saved.ProtectedPorts, []int{1234}) {
		t.Fatal("last applied ports not persisted", saved)
	}
	saved.ProtectedPorts[0] = 5678
	unchanged, _, _, _ := loaded.snapshot()
	if unchanged.ProtectedPorts[0] != 1234 {
		t.Fatal("snapshot alias changed stored ports")
	}
}

func TestUPnPPortsNativeTransaction(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture runs under Linux without host access")
	}
	for _, scenario := range []string{"commit", "rollback", "EOF", "conflict", "foreign", "runtime-failure", "lease-race"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range []string{"etc/config", "etc/init.d", "var/lock", "var/etc", "var/run", "tmp", "proc/98765", "bin"} {
				if err := os.MkdirAll(filepath.Join(root, d), 0700); err != nil {
					t.Fatal(err)
				}
			}
			exe, _ := os.Executable()
			os.WriteFile(filepath.Join(root, "bin/uci"), []byte("#!/bin/sh\nexec "+upnpShellQuote(exe)+" -test.run='^TestUPnPToolHelper$' -- uci \"$@\"\n"), 0700)
			lease := filepath.Join(root, "tmp/upnp.leases")
			leaseData := "TCP:4567:192.168.1.2:8000:0:original\n"
			if scenario == "conflict" {
				leaseData = "UDP:6881:192.168.1.2:8000:0:existing\n"
			}
			os.WriteFile(lease, []byte(leaseData), 0600)
			config := map[string]map[string]string{
				"config":        {"type": "upnpd", "secure_mode": "0", "upnp_lease_file": lease},
				"allow":         {"type": "perm_rule", "action": "allow", "ext_ports": "1024-65535", "int_addr": "0.0.0.0/0", "int_ports": "1024-65535"},
				"deny":          {"type": "perm_rule", "action": "deny", "ext_ports": "0-65535", "int_addr": "0.0.0.0/0", "int_ports": "0-65535"},
				"fixture_order": {"ids": "config allow deny"},
			}
			if scenario == "foreign" {
				config["lnport_6881"] = map[string]string{"type": "perm_rule", "action": "allow"}
			}
			b, _ := json.Marshal(config)
			file := filepath.Join(root, "etc/config/upnpd")
			os.WriteFile(file, b, 0600)
			init := `#!/bin/sh
[ ! -e "/proc/$$/fd/9" ] || { echo 'lock inherited' >&2; exit 1; }
tmpconf="/var/etc/miniupnpd.conf"
conf_rule_add() {
 s="$1"
 action=$(uci -q get "upnpd.$s.action")
 external=$(uci -q get "upnpd.$s.ext_ports")
 address=$(uci -q get "upnpd.$s.int_addr")
 internal=$(uci -q get "upnpd.$s.int_ports")
 echo "$action $external $address $internal" >>"$tmpconf"
}
config_foreach() {
 for s in $(uci -q show upnpd | sed -n 's/^upnpd\.\([^=]*\)=perm_rule$/\1/p'); do conf_rule_add "$s"; done
}
case "$1" in
start)
 printf '98765\n' >"$LINKNEST_UPNP_TOOL_ROOT/var/run/miniupnpd.pid"
 echo miniupnpd >"$LINKNEST_UPNP_TOOL_ROOT/proc/98765/cmdline"
 : >"$tmpconf"
 config_foreach conf_rule_add perm_rule "$tmpconf"
 if [ "$LINKNEST_PORT_TEST" = runtime-failure ] && uci -q get upnpd.lnport_6881 >/dev/null; then echo 'allow 0-65535 0.0.0.0/0 0-65535' >"$tmpconf"; fi
 ;;
stop)
 if [ "$LINKNEST_PORT_TEST" = lease-race ] && [ ! -f "$LINKNEST_UPNP_TOOL_ROOT/raced" ]; then
  echo 'UDP:6881:192.168.1.9:9000:0:raced' >>"$LINKNEST_UPNP_TOOL_ROOT/tmp/upnp.leases"
  touch "$LINKNEST_UPNP_TOOL_ROOT/raced"
 fi
 ;;
esac
`
			init = strings.ReplaceAll(init, "/var/etc/", root+"/var/etc/")
			initFile := filepath.Join(root, "etc/init.d/miniupnpd")
			os.WriteFile(initFile, []byte(init), 0700)
			run := func(ports []int, decision string) ([]byte, error) {
				script, err := buildUPnPPortsScript(ports)
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range []string{"/etc/init.d/", "/etc/config/", "/var/lock/", "/var/etc/", "/var/run/", "/tmp/upnp.leases", "/tmp/linknest-upnp-ports.", "/proc/$pid/"} {
					script = strings.ReplaceAll(script, p, root+p)
				}
				cmd := exec.Command("sh", "-c", script)
				if decision != "EOF" {
					cmd.Stdin = strings.NewReader(decision + "\n")
				}
				cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+":"+os.Getenv("PATH"), "LINKNEST_UPNP_TOOL_ROOT="+root, "LINKNEST_PORT_TEST="+scenario)
				return cmd.CombinedOutput()
			}
			decision := "COMMIT"
			if scenario == "rollback" {
				decision = "ROLLBACK"
			}
			if scenario == "EOF" {
				decision = "EOF"
			}
			out, err := run([]int{6082, 6881}, decision)
			if scenario == "commit" {
				if err != nil || !strings.Contains(string(out), "LINKNEST_UPNP_PORTS_OK") {
					t.Fatalf("%v %s", err, out)
				}
				var applied map[string]map[string]string
				data, _ := os.ReadFile(file)
				json.Unmarshal(data, &applied)
				if applied["allow"]["action"] != "allow" || applied["config"]["secure_mode"] != "0" {
					t.Fatal("unrelated native settings changed")
				}
				out, err = run(nil, "COMMIT")
				if err != nil {
					t.Fatalf("disable: %v %s", err, out)
				}
				data, _ = os.ReadFile(file)
				json.Unmarshal(data, &applied)
				// Decode into a fresh map: removed keys must not be retained by JSON unmarshal.
				applied = nil
				json.Unmarshal(data, &applied)
				if applied["lnport_6881"] != nil || applied["allow"]["action"] != "allow" {
					t.Fatal("owned rules not removed safely")
				}
			} else {
				if err == nil {
					t.Fatalf("expected guarded failure: %s", out)
				}
				data, _ := os.ReadFile(file)
				if string(data) != string(b) {
					t.Fatalf("failed transaction changed configuration: %s", out)
				}
			}
			kept, _ := os.ReadFile(lease)
			if !strings.HasPrefix(string(kept), leaseData) {
				t.Fatal("original lease lost")
			}
			if scenario == "lease-race" && !strings.Contains(string(kept), "raced") {
				t.Fatal("racing client mapping was deleted")
			}
			unchanged, _ := os.ReadFile(initFile)
			if string(unchanged) != init {
				t.Fatal("native startup script changed")
			}
		})
	}
}
