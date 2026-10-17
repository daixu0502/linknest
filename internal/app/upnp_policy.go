package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const upnpPolicyChain = "LNEST_UPNP"

// No new daemon, router agent, docker socket or host PID namespace is needed.
// SSH credentials exist only for this request. The router's ordinary fw3 UCI
// rules persist over reboot; the scoped live chains avoid a firewall restart.
func buildUPnPPolicy(c UPnPConfig) (string, error) {
	if err := validateUPnPConfig(&c); err != nil {
		return "", err
	}
	u, err := upnpEndpoint(c.DescriptionURL)
	if err != nil {
		return "", err
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	if p, _ := strconv.Atoi(port); p < 1024 {
		return "", errors.New("为避免拦截路由器管理等系统服务，黑名单要求 UPnP HTTP 使用 1024 以上的独立端口")
	}
	var commands, filter4, filter6 strings.Builder
	for _, b := range c.Blacklist {
		if !b.Enabled {
			continue
		}
		address, mac, err := upnpBlockAddress(b.Address)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(b.ID))
		id := "lnupnp_" + hex.EncodeToString(sum[:8])
		for _, proto := range []string{"tcp", "udp"} {
			p := port
			if proto == "udp" {
				p = "5351"
			}
			section := id + "_" + proto
			fmt.Fprintf(&commands, "if U -q get %s >/dev/null 2>&1; then echo '同名 UCI 节已存在，未覆盖' >&2; exit 1; fi\n", upnpShellQuote("firewall."+section))
			for _, pair := range [][2]string{{"", "rule"}, {"name", "LinkNest UPnP " + section}, {"linknest_owner", "upnp-v1"}, {"src", c.LANZone}, {"proto", proto}, {"dest_port", p}, {"target", "REJECT"}, {"enabled", "1"}} {
				key := "firewall." + section
				if pair[0] != "" {
					key += "." + pair[0]
				}
				fmt.Fprintf(&commands, "U set %s\n", upnpShellQuote(key+"="+pair[1]))
			}
			match := "-s " + address
			if mac {
				match = "-m mac --mac-source " + address
				fmt.Fprintf(&commands, "U set %s\n", upnpShellQuote("firewall."+section+".src_mac="+address))
				fmt.Fprintf(&commands, "U set %s\n", upnpShellQuote("firewall."+section+".family=any"))
			} else {
				fmt.Fprintf(&commands, "U set %s\n", upnpShellQuote("firewall."+section+".src_ip="+address))
				fmt.Fprintf(&commands, "U set %s\n", upnpShellQuote("firewall."+section+".family=ipv4"))
			}
			line := fmt.Sprintf("-A %s %s -p %s --dport %s -m comment --comment %s -j DROP\n", upnpPolicyChain, match, proto, p, section)
			filter4.WriteString(line)
			if mac {
				filter6.WriteString(line)
			}
		}
	}
	restore := func(rules string) string {
		return "*filter\n:" + upnpPolicyChain + " - [0:0]\n-F " + upnpPolicyChain + "\n" + rules + "-A " + upnpPolicyChain + " -j RETURN\nCOMMIT\n"
	}
	script := `set -eu
umask 077
for cmd in uci iptables ip6tables iptables-restore ip6tables-restore md5sum flock mktemp; do command -v "$cmd" >/dev/null || { echo "缺少原厂命令: $cmd" >&2; exit 1; }; done
[ -f /etc/config/firewall ] || { echo '仅支持 OpenWrt/fw3 原厂防火墙' >&2; exit 1; }
exec 9>/var/lock/linknest-upnp-policy.lock
flock -n 9 || { echo '其他黑名单操作正在执行' >&2; exit 1; }
[ -z "$(uci -q changes firewall)" ] || { echo '原厂防火墙有未提交修改，请先处理' >&2; exit 1; }
zone_found=0
for section in $(uci -q show firewall | sed -n 's/^firewall\.\([^=]*\)=zone$/\1/p'); do
 [ "$(uci -q get "firewall.$section.name")" != ` + upnpShellQuote(c.LANZone) + ` ] || zone_found=1
done
[ "$zone_found" = 1 ] || { echo 'LAN 防火墙区域不存在，未修改规则' >&2; exit 1; }
work=$(mktemp -d /tmp/linknest-upnp.XXXXXX)
case "$work" in /tmp/linknest-upnp.*) ;; *) exit 1 ;; esac
mkdir "$work/delta"
cp /etc/config/firewall "$work/firewall"
cp /etc/config/firewall "$work/original"
oldsum=$(md5sum /etc/config/firewall | cut -d ' ' -f 1)
committed=0
done_ok=0
U() { uci -c "$work" -P "$work/delta" "$@"; }
backup_chain() {
 bin="$1"; suffix="$2"
 if "$bin" -w 3 -C INPUT -j LNEST_UPNP 2>/dev/null; then echo 1 >"$work/hooked-$suffix"; else echo 0 >"$work/hooked-$suffix"; fi
 if "$bin" -w 3 -S LNEST_UPNP >"$work/old-$suffix" 2>/dev/null; then
  echo 1 >"$work/existed-$suffix"
 else
  echo 0 >"$work/existed-$suffix"; : >"$work/old-$suffix"
 fi
}
rollback_chain() {
 bin="$1"; restore="$2"; suffix="$3"
 if [ "$(cat "$work/existed-$suffix")" = 1 ]; then
  { echo '*filter'; echo '-F LNEST_UPNP'; sed -n '/^-A /p' "$work/old-$suffix"; echo COMMIT; } | "$restore" -w 3 --noflush
  if [ "$(cat "$work/hooked-$suffix")" = 0 ]; then "$bin" -w 3 -D INPUT -j LNEST_UPNP 2>/dev/null || true; fi
 else
  "$bin" -w 3 -D INPUT -j LNEST_UPNP 2>/dev/null || true
  "$bin" -w 3 -F LNEST_UPNP 2>/dev/null || true
  "$bin" -w 3 -X LNEST_UPNP 2>/dev/null || true
 fi
}
cleanup() {
 if [ "$done_ok" != 1 ] && [ "$committed" = 1 ]; then
  rollback_chain iptables iptables-restore 4 || echo 'IPv4 回滚失败，请手动核对' >&2
  rollback_chain ip6tables ip6tables-restore 6 || echo 'IPv6 回滚失败，请手动核对' >&2
  current=$(md5sum /etc/config/firewall | cut -d ' ' -f 1)
  if [ "$current" = "$newsum" ]; then
   cp "$work/original" /etc/config/.linknest-upnp-restore-$$
   mv /etc/config/.linknest-upnp-restore-$$ /etc/config/firewall
  else
   echo '检测到并发配置修改，未覆盖原厂配置；请手动核对' >&2
  fi
 fi
 case "$work" in /tmp/linknest-upnp.*) rm -rf -- "$work" ;; esac
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
for section in $(U -q show firewall | sed -n 's/^firewall\.\(lnupnp_[a-zA-Z0-9_]*\)=rule$/\1/p'); do
 [ "$(U -q get "firewall.$section.linknest_owner")" = upnp-v1 ] || { echo '同名前缀已被其他配置占用' >&2; exit 1; }
 U delete "firewall.$section"
done
` + commands.String() + `
U commit firewall
cat >"$work/new4" <<'LINKNEST_FILTER4'
` + restore(filter4.String()) + `LINKNEST_FILTER4
cat >"$work/new6" <<'LINKNEST_FILTER6'
` + restore(filter6.String()) + `LINKNEST_FILTER6
backup_chain iptables 4
backup_chain ip6tables 6
iptables-restore -w 3 --test --noflush <"$work/new4"
ip6tables-restore -w 3 --test --noflush <"$work/new6"
[ "$(md5sum /etc/config/firewall | cut -d ' ' -f 1)" = "$oldsum" ] && [ -z "$(uci -q changes firewall)" ] || { echo '原厂配置已被并发修改，未覆盖' >&2; exit 1; }
newsum=$(md5sum "$work/firewall" | cut -d ' ' -f 1)
cp "$work/firewall" /etc/config/.linknest-upnp-new-$$
mv /etc/config/.linknest-upnp-new-$$ /etc/config/firewall
committed=1
iptables-restore -w 3 --noflush <"$work/new4"
ip6tables-restore -w 3 --noflush <"$work/new6"
iptables -w 3 -C INPUT -j LNEST_UPNP 2>/dev/null || iptables -w 3 -I INPUT 1 -j LNEST_UPNP
ip6tables -w 3 -C INPUT -j LNEST_UPNP 2>/dev/null || ip6tables -w 3 -I INPUT 1 -j LNEST_UPNP
done_ok=1
echo LINKNEST_UPNP_POLICY_OK
`
	return script, nil
}
func upnpShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

type upnpOutput struct{ bytes.Buffer }

func (b *upnpOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 65536 {
		left := 65536 - b.Len()
		if len(p) > left {
			p = p[:left]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}
func runUPnPPolicy(ctx context.Context, host SSHHost, password, privateKey, script string) error {
	var methods []ssh.AuthMethod
	if privateKey != "" {
		key, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return errors.New("SSH 私钥无效；仅支持未加密私钥，不会保存")
		}
		methods = []ssh.AuthMethod{ssh.PublicKeys(key)}
	} else if password != "" {
		methods = []ssh.AuthMethod{ssh.Password(password)}
	} else {
		return errors.New("请提供本次操作的 SSH 密码或私钥")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", host.Address)
	if err != nil {
		return errors.New("无法连接路由器 SSH")
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(18 * time.Second))
	cfg := &ssh.ClientConfig{User: host.Username, Auth: methods, Timeout: 5 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != host.Fingerprint {
			return errors.New("路由器 SSH 指纹变化，操作已中止；请重新核实指纹")
		}
		return nil
	}}
	conn, chans, reqs, err := ssh.NewClientConn(raw, host.Address, cfg)
	if err != nil {
		return fmt.Errorf("SSH 身份或指纹验证失败：%w", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return errors.New("无法建立 SSH 操作会话")
	}
	defer session.Close()
	var out, stderr upnpOutput
	session.Stdout, session.Stderr = &out, &stderr
	session.Stdin = strings.NewReader(script)
	if err = session.Run("sh -s"); err != nil {
		return fmt.Errorf("路由器黑名单应用失败：%s", strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(out.String()) != "LINKNEST_UPNP_POLICY_OK" {
		return errors.New("路由器未返回完整应用确认，请核对原厂规则后再试")
	}
	return nil
}
func upnpARPMACs() map[string]string {
	out := map[string]string{}
	b, _ := os.ReadFile("/proc/net/arp")
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[2] != "0x0" {
			if mac, err := net.ParseMAC(fields[3]); err == nil {
				out[fields[0]] = strings.ToUpper(mac.String())
			}
		}
	}
	return out
}
func upnpBlockedMapping(c UPnPConfig, m UPnPMapping, macs map[string]string) bool {
	for _, b := range c.Blacklist {
		if !b.Enabled {
			continue
		}
		address, mac, _ := upnpBlockAddress(b.Address)
		if mac {
			if macs[m.InternalIP] == address {
				return true
			}
		} else {
			_, network, _ := net.ParseCIDR(address)
			if network != nil && network.Contains(net.ParseIP(m.InternalIP)) {
				return true
			}
		}
	}
	return false
}
