package app

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestUPnPModeSSHHandshake(t *testing.T) {
	for _, scenario := range []string{"commit", "rollback", "fingerprint"} {
		t.Run(scenario, func(t *testing.T) {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			signer, _ := ssh.NewSignerFromKey(key)
			config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
				if string(p) != "test-only" {
					return nil, errors.New("bad credentials")
				}
				return nil, nil
			}}
			config.AddHostKey(signer)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			decision := make(chan string, 1)
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn, chans, reqs, err := ssh.NewServerConn(raw, config)
				if err != nil {
					decision <- "key-rejected"
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for incoming := range chans {
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					defer channel.Close()
					for req := range requests {
						if req.Type != "exec" {
							req.Reply(false, nil)
							continue
						}
						var payload struct{ Command string }
						ssh.Unmarshal(req.Payload, &payload)
						if !strings.HasPrefix(payload.Command, "sh -c '") || !strings.Contains(payload.Command, "LINKNEST_UPNP_MODE_READY") {
							req.Reply(false, nil)
							return
						}
						req.Reply(true, nil)
						fmt.Fprintln(channel, "LINKNEST_UPNP_MODE_READY")
						line, _ := bufio.NewReader(channel).ReadString('\n')
						decision <- strings.TrimSpace(line)
						status := uint32(1)
						if strings.TrimSpace(line) == "COMMIT" {
							status = 0
							fmt.Fprintln(channel, "LINKNEST_UPNP_MODE_OK")
						}
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
						return
					}
				}
			}()
			host := SSHHost{Username: "root", Address: ln.Addr().String(), Fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
			if scenario == "fingerprint" {
				host.Fingerprint = "SHA256:incorrect"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = runUPnPMode(ctx, host, "test-only", "", true, func(context.Context) error {
				if scenario == "rollback" {
					return errors.New("mapping verification fixture failure")
				}
				return nil
			})
			want := "COMMIT"
			if scenario == "rollback" {
				want = "ROLLBACK"
			}
			if scenario == "fingerprint" {
				want = "key-rejected"
			}
			select {
			case got := <-decision:
				if got != want {
					t.Fatal(got, want)
				}
			case <-ctx.Done():
				t.Fatal("SSH fixture timed out")
			}
			if (err == nil) != (scenario == "commit") {
				t.Fatal(scenario, err)
			}
		})
	}
}
