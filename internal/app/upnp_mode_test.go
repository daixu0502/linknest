package app

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUPnPModeTwoPhaseScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture runs in ARM64 isolation")
	}
	for _, decision := range []string{"COMMIT", "ROLLBACK", "EOF"} {
		t.Run(decision, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range []string{"etc/config", "etc/init.d", "var/lock", "var/etc", "var/run", "tmp", "proc/98765", "bin"} {
				if err := os.MkdirAll(filepath.Join(root, d), 0700); err != nil {
					t.Fatal(err)
				}
			}
			exe, _ := os.Executable()
			stub := "#!/bin/sh\nexec " + upnpShellQuote(exe) + " -test.run='^TestUPnPToolHelper$' -- uci \"$@\"\n"
			os.WriteFile(filepath.Join(root, "bin/uci"), []byte(stub), 0700)
			lease := filepath.Join(root, "tmp/upnp.leases")
			os.WriteFile(lease, []byte("preserved lease fixture\n"), 0600)
			config := map[string]map[string]string{"config": {"type": "upnpd", "secure_mode": "1", "upnp_lease_file": lease, "unrelated": "keep"}}
			b, _ := json.Marshal(config)
			configFile := filepath.Join(root, "etc/config/upnpd")
			os.WriteFile(configFile, b, 0600)
			init := `#!/bin/sh
tmpconf="/var/etc/miniupnpd.conf"
service_start() {
 printf '%s\000' "$@" >"$LINKNEST_UPNP_TOOL_ROOT/proc/98765/cmdline"
 printf '98765\n' >"$LINKNEST_UPNP_TOOL_ROOT/var/run/miniupnpd.pid"
 secure=$(uci -q get upnpd.config.secure_mode)
 if [ "$secure" = 0 ]; then echo secure_mode=no >"$tmpconf"; else echo secure_mode=yes >"$tmpconf"; fi
}
case "$1" in
start)
 service_start /usr/sbin/miniupnpd -S -f $tmpconf
 ;;
stop) : ;;
esac
`
			init = strings.ReplaceAll(init, "/var/etc/", root+"/var/etc/")
			initFile := filepath.Join(root, "etc/init.d/miniupnpd")
			os.WriteFile(initFile, []byte(init), 0700)
			run := func(allow bool, decision string) ([]byte, error) {
				script := buildUPnPModeScript(allow)
				for _, p := range []string{"/etc/init.d/", "/etc/config/", "/var/lock/", "/var/etc/", "/var/run/", "/tmp/upnp.leases", "/tmp/linknest-upnp-mode.", "/proc/"} {
					script = strings.ReplaceAll(script, p, root+p)
				}
				// /var/run/miniupnpd.leases was already handled by the broader prefix.
				cmd := exec.Command("sh", "-c", script)
				if decision != "EOF" {
					cmd.Stdin = strings.NewReader(decision + "\n")
				}
				cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+":"+os.Getenv("PATH"), "LINKNEST_UPNP_TOOL_ROOT="+root, "LINKNEST_UPNP_TOOL_MODE=mode")
				return cmd.CombinedOutput()
			}
			out, err := run(true, decision)
			if decision == "COMMIT" {
				if err != nil || !strings.Contains(string(out), "LINKNEST_UPNP_MODE_OK") {
					t.Fatalf("enable: %v %s", err, out)
				}
				newInit, _ := os.ReadFile(initFile)
				if strings.Contains(string(newInit), "miniupnpd -S -f") {
					t.Fatal("secure launch flag not removed")
				}
				out, err = run(false, "COMMIT")
				if err != nil || !strings.Contains(string(out), "LINKNEST_UPNP_MODE_OK") {
					t.Fatalf("disable: %v %s", err, out)
				}
				newInit, _ = os.ReadFile(initFile)
				if !strings.Contains(string(newInit), "miniupnpd -S -f") {
					t.Fatal("secure launch flag not restored")
				}
			} else {
				if err == nil {
					t.Fatal("rollback/EOF committed")
				}
				restored, _ := os.ReadFile(initFile)
				original, _ := os.ReadFile(configFile)
				if string(restored) != init || string(original) != string(b) {
					t.Fatalf("failed switch did not restore files: %s", out)
				}
			}
			kept, _ := os.ReadFile(lease)
			if string(kept) != "preserved lease fixture\n" {
				t.Fatal("lease changed")
			}
		})
	}
}

func TestUPnPModePreservesMappings(t *testing.T) {
	m := UPnPMapping{Protocol: "TCP", ExternalPort: 12345, InternalIP: "192.168.1.2", InternalPort: 80, Description: "original", LeaseSeconds: 60}
	current := m
	current.LeaseSeconds = 55
	if err := upnpVerifyPreserved([]UPnPMapping{m}, []UPnPMapping{current}, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := upnpVerifyPreserved([]UPnPMapping{m}, nil, time.Second); err == nil {
		t.Fatal("missing mapping accepted")
	}
	if err := upnpVerifyPreserved([]UPnPMapping{m}, nil, 61*time.Second); err != nil {
		t.Fatal("naturally expired mapping blocked switch", err)
	}
	m.LeaseSeconds = 0
	if err := upnpVerifyPreserved([]UPnPMapping{m}, nil, time.Hour); err == nil {
		t.Fatal("lost permanent mapping accepted")
	}
}
