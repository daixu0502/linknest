package app

import (
	"context"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
	"time"
)

// Stop at host-key exchange, before sending a password or private-key proof.
func probeSSH(ctx context.Context, address string) (string, error) {
	host, _, err := hostPort(address)
	if err != nil || host == "" {
		return "", errors.New("请填写 SSH 主机:端口")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "", errors.New("SSH 主机不可达，请检查地址与端口")
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(8 * time.Second))
	fingerprint := ""
	cfg := &ssh.ClientConfig{User: "linknest-host-key-probe", HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(key)
		return errors.New("host key collected")
	}}
	_, _, _, err = ssh.NewClientConn(raw, address, cfg)
	if fingerprint != "" {
		return fingerprint, nil
	}
	return "", errors.New("无法从 SSH 握手取得主机指纹，请检查 SSH 服务与算法兼容性")
}
func (a *App) sshTrust(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ID            string `json:"id"`
		Address       string `json:"address"`
		Previous      string `json:"previous"`
		Fingerprint   string `json:"fingerprint"`
		AdminPassword string `json:"adminPassword"`
	}
	if !decode(w, r, &q) {
		return
	}
	a.mu.Lock()
	hash := a.auth.PasswordHash
	a.mu.Unlock()
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(q.AdminPassword)) != nil {
		fail(w, 403, "管理员二次验证失败")
		return
	}
	select {
	case a.terminalSlots <- struct{}{}:
		defer func() { <-a.terminalSlots }()
	default:
		fail(w, 429, "正在连接，请稍后再试")
		return
	}
	actual, err := probeSSH(r.Context(), q.Address)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if actual != q.Fingerprint {
		fail(w, 409, "指纹再次变化，请取消并重新连接核对")
		return
	}
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	c := a.store.snapshot()
	for i, h := range c.SSHHosts {
		if h.ID == q.ID {
			if h.Address != q.Address || h.Fingerprint != q.Previous {
				fail(w, 409, "主机配置已改变，请刷新后重新连接")
				return
			}
			c.SSHHosts[i].Fingerprint = actual
			if err = a.store.save(c); err != nil {
				fail(w, 500, "保存指纹失败")
				return
			}
			a.event("info", "用户确认并保存 SSH 主机指纹："+h.Name)
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	fail(w, 404, "SSH 主机不存在")
}
func (a *App) sshProbe(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Address string `json:"address"`
	}
	if !decode(w, r, &q) {
		return
	}
	select {
	case a.terminalSlots <- struct{}{}:
		defer func() { <-a.terminalSlots }()
	default:
		fail(w, 429, "正在连接，请稍后再试")
		return
	}
	fp, err := probeSSH(r.Context(), q.Address)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	respond(w, 200, map[string]any{"ok": true, "fingerprint": fp})
}
