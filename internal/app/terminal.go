package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

func (a *App) terminal(w http.ResponseWriter, r *http.Request) {
	c := a.store.snapshot()
	if !c.TerminalEnabled {
		fail(w, 403, "Web 终端默认关闭，请先在设置中启用")
		return
	}
	if !sameOrigin(r) || r.Header.Get("Origin") == "" {
		fail(w, 403, "终端来源校验失败")
		return
	}
	var host *SSHHost
	for _, h := range c.SSHHosts {
		if h.ID == r.URL.Query().Get("id") {
			v := h
			host = &v
			break
		}
	}
	if host == nil {
		fail(w, 404, "SSH 主机不存在")
		return
	}
	select {
	case a.terminalSlots <- struct{}{}:
		defer func() { <-a.terminalSlots }()
	default:
		fail(w, 429, "最多同时打开两个终端")
		return
	}
	up := websocket.Upgrader{CheckOrigin: sameOrigin, ReadBufferSize: 4096, WriteBufferSize: 4096}
	ws, e := up.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	defer ws.Close()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	ck, _ := r.Cookie(adminCookieName(r))
	if ck == nil {
		return
	}
	a.mu.Lock()
	session, validSession := a.sessions[ck.Value]
	if !validSession || time.Now().After(session.expires) || !a.store.snapshot().TerminalEnabled {
		a.mu.Unlock()
		return
	}
	remove := a.terminals.add(ck.Value, func() { cancel(); ws.Close() })
	a.mu.Unlock()
	defer remove()
	ws.SetReadLimit(16384)
	ws.SetReadDeadline(time.Now().Add(20 * time.Second))
	var q struct {
		AdminPassword string `json:"adminPassword"`
		Password      string `json:"password"`
		PrivateKey    string `json:"privateKey"`
	}
	if ws.ReadJSON(&q) != nil {
		return
	}
	a.mu.Lock()
	hash := a.auth.PasswordHash
	a.mu.Unlock()
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(q.AdminPassword)) != nil {
		ws.WriteJSON(map[string]string{"error": "管理员二次验证失败"})
		return
	}
	auth := []ssh.AuthMethod{}
	if q.PrivateKey != "" {
		key, err := ssh.ParsePrivateKey([]byte(q.PrivateKey))
		if err != nil {
			ws.WriteJSON(map[string]string{"error": "私钥格式不正确；首版仅支持未加密私钥，且不会保存"})
			return
		}
		auth = append(auth, ssh.PublicKeys(key))
	} else {
		auth = append(auth, ssh.Password(q.Password))
	}
	conf := &ssh.ClientConfig{User: host.Username, Auth: auth, Timeout: 8 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		actual := ssh.FingerprintSHA256(key)
		if actual != host.Fingerprint {
			return fmt.Errorf("主机指纹不匹配：%s", actual)
		}
		return nil
	}}
	raw, e := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", host.Address)
	if e != nil {
		ws.WriteJSON(map[string]string{"error": "SSH 主机不可达"})
		return
	}
	stopCancel := context.AfterFunc(ctx, func() { raw.Close() })
	defer stopCancel()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	cc, chans, reqs, e := ssh.NewClientConn(raw, host.Address, conf)
	if e != nil {
		raw.Close()
		ws.WriteJSON(map[string]string{"error": "SSH 握手或身份验证失败：" + e.Error()})
		return
	}
	raw.SetDeadline(time.Time{})
	conn := ssh.NewClient(cc, chans, reqs)
	q.Password = ""
	q.PrivateKey = ""
	q.AdminPassword = ""
	if e != nil {
		ws.WriteJSON(map[string]string{"error": "SSH 连接失败：" + e.Error()})
		return
	}
	defer conn.Close()
	ss, e := conn.NewSession()
	if e != nil {
		return
	}
	defer ss.Close()
	stdin, e := ss.StdinPipe()
	if e != nil {
		return
	}
	output, e := ss.StdoutPipe()
	if e != nil {
		return
	}
	ss.Stderr = ss.Stdout
	if e = ss.RequestPty("xterm", 30, 100, ssh.TerminalModes{ssh.ECHO: 1}); e != nil {
		ws.WriteJSON(map[string]string{"error": "PTY 创建失败"})
		return
	}
	if e = ss.Shell(); e != nil {
		return
	}
	a.event("info", "已打开 SSH 终端："+host.Name+"（最多 15 分钟，不记录命令内容）")
	defer a.event("info", "SSH 终端已关闭："+host.Name)
	lifetime := min(15*time.Minute, time.Until(session.expires))
	timer := time.AfterFunc(lifetime, func() { ws.Close(); conn.Close() })
	defer timer.Stop()
	ws.SetReadDeadline(time.Now().Add(15 * time.Minute))
	var writeMu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ws.Close()
		buf := make([]byte, 4096)
		for {
			n, err := output.Read(buf)
			if n > 0 {
				writeMu.Lock()
				e := ws.WriteMessage(websocket.BinaryMessage, buf[:n])
				writeMu.Unlock()
				if e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		kind, b, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if kind == websocket.TextMessage {
			var resize struct {
				Cols int `json:"cols"`
				Rows int `json:"rows"`
			}
			if json.Unmarshal(b, &resize) == nil && resize.Cols > 0 && resize.Cols <= 300 && resize.Rows > 0 && resize.Rows <= 100 {
				ss.WindowChange(resize.Rows, resize.Cols)
				continue
			}
		}
		if kind != websocket.BinaryMessage {
			continue
		}
		if len(b) > 8192 {
			ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1009, "input too large"), time.Now().Add(time.Second))
			return
		}
		if _, err = stdin.Write(b); err != nil && !errors.Is(err, net.ErrClosed) {
			return
		}
	}
}
