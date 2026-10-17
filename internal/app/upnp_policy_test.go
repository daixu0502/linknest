package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUPnPPolicyNativeDryRun(t *testing.T) {
	if os.Getenv("LINKNEST_UPNP_NATIVE_DRY_RUN") != "1" {
		t.Skip("opt-in OpenWrt native preflight; no commit or firewall installation")
	}
	c := UPnPConfig{Enabled: true, DescriptionURL: "http://192.168.255.1:5351/rootDesc.xml", LANZone: "lan", Blacklist: []UPnPBlock{{ID: "preflight", Address: "192.168.255.253", Enabled: true}, {ID: "preflightmac", Address: "02:00:00:00:00:01", Enabled: true}}}
	script, err := buildUPnPPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	marker := "[ \"$(md5sum /etc/config/firewall | cut -d ' ' -f 1)\" = \"$oldsum\" ]"
	prefix, _, ok := strings.Cut(script, marker)
	if !ok || strings.Contains(prefix, "committed=1") {
		t.Fatal("unsafe dry-run boundary")
	}
	// Only staged UCI and iptables-restore --test are reached. committed stays
	// zero, so the EXIT trap only removes our own temporary working directory.
	script = prefix + "\ndone_ok=1\necho LINKNEST_UPNP_DRY_RUN_OK\n"
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "LINKNEST_UPNP_DRY_RUN_OK") {
		t.Fatalf("native dry-run failed: %v: %s", err, out)
	}
	t.Log("Native UCI staging and IPv4/IPv6 --test passed; no persistent or live rules installed")
	for _, allow := range []bool{false, true} {
		modeScript := buildUPnPModeScript(allow)
		prefix, _, ok := strings.Cut(modeScript, "cp -p \"$work/init-new\" /etc/init.d/.linknest-upnp-new-$$")
		if !ok || strings.Contains(prefix, "changed=1") {
			t.Fatal("unsafe mode preflight boundary")
		}
		cmd := exec.Command("sh", "-s")
		cmd.Stdin = strings.NewReader(prefix + "\ncommitted=1\necho LINKNEST_UPNP_MODE_PREFLIGHT_OK\n")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "LINKNEST_UPNP_MODE_PREFLIGHT_OK") {
			t.Fatalf("mode preflight %v: %v %s", allow, err, out)
		}
	}
	t.Log("Both native launch-mode templates and staged UCI passed; no service restart or original file changes")
}

// Execute the real transaction script against fake UCI/iptables programs in a
// temporary filesystem. Never grants NET_ADMIN or touches host /etc/config.
func TestUPnPPolicyTransaction(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX shell; covered in ARM64 isolation")
	}
	for _, mode := range []string{"success", "live6", "syntax6", "concurrent", "pending", "foreign-owner"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"etc/config", "var/lock", "tmp", "bin", "state"} {
				os.MkdirAll(filepath.Join(root, dir), 0700)
			}
			original := map[string]map[string]string{"lan": {"type": "zone", "name": "lan"}, "foreign": {"type": "rule", "name": "User existing rule", "dest_port": "443"}}
			if mode == "foreign-owner" {
				original["lnupnp_foreign"] = map[string]string{"type": "rule", "name": "not owned"}
			}
			file := filepath.Join(root, "etc/config/firewall")
			data, _ := json.Marshal(original)
			os.WriteFile(file, data, 0600)
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"uci", "iptables", "ip6tables", "iptables-restore", "ip6tables-restore"} {
				stub := "#!/bin/sh\nexec " + upnpShellQuote(exe) + " -test.run='^TestUPnPToolHelper$' -- " + upnpShellQuote(tool) + " \"$@\"\n"
				os.WriteFile(filepath.Join(root, "bin", tool), []byte(stub), 0700)
			}
			c := UPnPConfig{Enabled: true, DescriptionURL: "http://192.168.1.1:5351/rootDesc.xml", LANZone: "lan", Blacklist: []UPnPBlock{{ID: "one", Address: "192.168.1.20", Enabled: true}, {ID: "two", Address: "2C-F0-5D-E0-69-6D", Enabled: true}}}
			script, err := buildUPnPPolicy(c)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{"/etc/config/", "/var/lock/", "/tmp/linknest-upnp."} {
				script = strings.ReplaceAll(script, p, root+p)
			}
			cmd := exec.Command("sh", "-s")
			cmd.Stdin = strings.NewReader(script)
			cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+":"+os.Getenv("PATH"), "LINKNEST_UPNP_TOOL_ROOT="+root, "LINKNEST_UPNP_TOOL_MODE="+mode)
			out, err := cmd.CombinedOutput()
			if mode == "success" && err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if mode != "success" && err == nil {
				t.Fatalf("expected safeguarded failure: %s", out)
			}
			current, _ := os.ReadFile(file)
			var parsed map[string]map[string]string
			json.Unmarshal(current, &parsed)
			if parsed["foreign"]["dest_port"] != "443" {
				t.Fatal("changed unrelated rule", string(current))
			}
			if mode == "success" {
				if !strings.Contains(string(out), "LINKNEST_UPNP_POLICY_OK") || len(parsed) != 6 {
					t.Fatal(string(out), string(current))
				}
				for _, suffix := range []string{"4", "6"} {
					b, _ := os.ReadFile(filepath.Join(root, "state", suffix))
					if !strings.Contains(string(b), "--dport 5351") {
						t.Fatal("live policy missing", suffix)
					}
				}
			} else if mode == "concurrent" {
				if parsed["concurrent"]["name"] != "external edit" {
					t.Fatal("overwrote concurrent change")
				}
			}
			if mode == "live6" || mode == "syntax6" || mode == "pending" || mode == "foreign-owner" {
				if string(current) != string(data) {
					t.Fatal("failed operation changed original config", string(current), string(out))
				}
			}
			if mode != "success" {
				for _, suffix := range []string{"4", "6"} {
					if _, err := os.Stat(filepath.Join(root, "state", suffix)); !os.IsNotExist(err) {
						t.Fatal("failed operation left live rules", suffix, string(out))
					}
				}
			}
		})
	}
}

func TestUPnPToolHelper(t *testing.T) {
	root := os.Getenv("LINKNEST_UPNP_TOOL_ROOT")
	if root == "" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(2)
	}
	tool, args := args[1], args[2:]
	mode := os.Getenv("LINKNEST_UPNP_TOOL_MODE")
	exit := func(code int) { os.Exit(code) }
	read := func(path string) map[string]map[string]string {
		b, err := os.ReadFile(path)
		if err != nil {
			exit(1)
		}
		var v map[string]map[string]string
		if json.Unmarshal(b, &v) != nil {
			exit(1)
		}
		return v
	}
	write := func(path string, v any) {
		b, _ := json.Marshal(v)
		if os.WriteFile(path, b, 0600) != nil {
			exit(1)
		}
	}
	if tool == "uci" {
		base := filepath.Join(root, "etc/config")
		i := 0
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			switch args[i] {
			case "-c":
				i++
				base = args[i]
			case "-P":
				i++
			}
			i++
		}
		args = args[i:]
		if len(args) < 1 {
			exit(2)
		}
		action := args[0]
		ref := "firewall"
		if len(args) > 1 {
			ref = args[1]
		}
		pkg := strings.SplitN(strings.SplitN(ref, "=", 2)[0], ".", 2)[0]
		v := read(filepath.Join(base, pkg))
		if action == "changes" {
			if mode == "pending" {
				fmt.Println("firewall.foreign.name='pending'")
			}
			exit(0)
		}
		if action == "commit" {
			exit(0)
		}
		if action == "show" {
			for id, values := range v {
				fmt.Printf("firewall.%s=%s\n", id, values["type"])
			}
			exit(0)
		}
		if action == "set" {
			key, value, ok := strings.Cut(ref, "=")
			if !ok {
				exit(2)
			}
			p := strings.Split(key, ".")
			if len(p) < 2 {
				exit(2)
			}
			if v[p[1]] == nil {
				v[p[1]] = map[string]string{}
			}
			field := "type"
			if len(p) > 2 {
				field = p[2]
			}
			v[p[1]][field] = value
			write(filepath.Join(base, pkg), v)
			exit(0)
		}
		p := strings.Split(ref, ".")
		if len(p) < 2 {
			exit(2)
		}
		if action == "delete" {
			delete(v, p[1])
			write(filepath.Join(base, pkg), v)
			exit(0)
		}
		if action == "get" {
			field := "type"
			if len(p) > 2 {
				field = p[2]
			}
			value, ok := v[p[1]][field]
			if !ok {
				exit(1)
			}
			fmt.Println(value)
			exit(0)
		}
		exit(2)
	}
	suffix := "4"
	if strings.HasPrefix(tool, "ip6") {
		suffix = "6"
	}
	state := filepath.Join(root, "state", suffix)
	if strings.HasSuffix(tool, "restore") {
		input, _ := io.ReadAll(os.Stdin)
		test := false
		for _, a := range args {
			if a == "--test" {
				test = true
			}
		}
		if suffix == "6" && test && mode == "syntax6" {
			fmt.Fprintln(os.Stderr, "fixture syntax failure")
			exit(1)
		}
		if suffix == "6" && test && mode == "concurrent" {
			file := filepath.Join(root, "etc/config/firewall")
			v := read(file)
			v["concurrent"] = map[string]string{"type": "rule", "name": "external edit"}
			write(file, v)
		}
		if test {
			exit(0)
		}
		if suffix == "6" && mode == "live6" {
			marker := filepath.Join(root, "state", "failure-once")
			if _, err := os.Stat(marker); os.IsNotExist(err) {
				os.WriteFile(marker, []byte("1"), 0600)
				fmt.Fprintln(os.Stderr, "fixture live apply failure")
				exit(1)
			}
		}
		var rules []string
		for _, line := range strings.Split(string(input), "\n") {
			if strings.HasPrefix(line, "-A ") {
				rules = append(rules, line)
			}
		}
		os.WriteFile(state, []byte(strings.Join(rules, "\n")+"\n"), 0600)
		exit(0)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-S ") {
		b, err := os.ReadFile(state)
		if err != nil {
			exit(1)
		}
		fmt.Printf("-N LNEST_UPNP\n%s", b)
		exit(0)
	}
	if strings.Contains(joined, "-C ") {
		if _, err := os.Stat(state + "-hook"); err != nil {
			exit(1)
		}
		exit(0)
	}
	if strings.Contains(joined, "-I ") {
		os.WriteFile(state+"-hook", []byte("1"), 0600)
		exit(0)
	}
	if strings.Contains(joined, "-D ") {
		os.Remove(state + "-hook")
		exit(0)
	}
	if strings.Contains(joined, "-F ") || strings.Contains(joined, "-X ") {
		os.Remove(state)
		exit(0)
	}
	exit(2)
}
