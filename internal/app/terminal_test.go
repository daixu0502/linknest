package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

func TestWebTerminalWithPinnedMockSSH(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if meta.User() == "tester" && string(p) == "test-only-ssh" {
			return nil, nil
		}
		return nil, fmt.Errorf("bad credentials")
	}}
	cfg.AddHostKey(signer)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		conn, chans, reqs, e := ssh.NewServerConn(c, cfg)
		if e != nil {
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(reqs)
		for n := range chans {
			ch, requests, e := n.Accept()
			if e != nil {
				return
			}
			go func() {
				defer ch.Close()
				for req := range requests {
					switch req.Type {
					case "pty-req", "window-change":
						req.Reply(true, nil)
					case "shell":
						req.Reply(true, nil)
						ch.Write([]byte("mock-shell-ready\r\n"))
						go io.Copy(ch, ch)
					default:
						req.Reply(false, nil)
					}
				}
			}()
		}
	}()
	a := testApp(t)
	cookie := signIn(t, a)
	c := a.store.snapshot()
	c.TerminalEnabled = true
	c.SSHHosts = []SSHHost{{ID: "test-host", Name: "Mock SSH", Address: ln.Addr().String(), Username: "tester", Fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}}
	a.store.save(c)
	srv := httptest.NewServer(a.handler())
	defer srv.Close()
	headers := http.Header{"Origin": {srv.URL}, "Cookie": {cookie.String()}}
	ws, _, e := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/api/terminal?id=test-host", headers)
	if e != nil {
		t.Fatal(e)
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	ws.WriteJSON(map[string]string{"adminPassword": "test-password-12345", "password": "test-only-ssh"})
	kind, b, e := ws.ReadMessage()
	if e != nil || kind != websocket.BinaryMessage || !strings.Contains(string(b), "mock-shell-ready") {
		t.Fatal("SSH bridge", kind, string(b), e)
	}
	ws.WriteMessage(websocket.BinaryMessage, []byte("echo-check"))
	_, b, e = ws.ReadMessage()
	if e != nil || string(b) != "echo-check" {
		t.Fatal("terminal input", string(b), e)
	}
}
