package app

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Opt-in fixture for an isolated Docker internal network, NEVER host mode.
// The three roles are run in separate namespaces, without production data.
func TestKernelLiveFixture(t *testing.T) {
	mode := os.Getenv("LINKNEST_KERNEL_TEST")
	if mode == "" {
		t.Skip("requires isolated Linux namespace fixture")
	}
	switch mode {
	case "backend":
		ln, err := net.Listen("tcp4", "0.0.0.0:33890")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		udp, err := net.ListenPacket("udp4", "0.0.0.0:33890")
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); io.Copy(c, c) }()
			}
		}()
		go func() {
			buf := make([]byte, 65535)
			for {
				n, a, err := udp.ReadFrom(buf)
				if err != nil {
					return
				}
				udp.WriteTo(buf[:n], a)
			}
		}()
		t.Log("backend ready")
		time.Sleep(90 * time.Second)
	case "gateway":
		f := newFirewall(true)
		r := Rule{ID: "isolated", Name: "isolated", Kind: "tcpudp", Network: "ipv4", ForwardMode: "kernel", Listen: "0.0.0.0:39642", Target: "172.29.228.2:33890", Enabled: true, OpenFirewall: true}
		if err := f.syncKernel([]Rule{r}, Config{}); err != nil {
			t.Fatal(err)
		}
		defer f.cleanupKernel()
		// Also parse whitelist/blacklist rules in the actual router kernel.
		if err := f.syncKernel([]Rule{r}, Config{Whitelist: []string{"172.29.228.4"}, Blacklist: []string{"172.29.228.0/24"}}); err != nil {
			t.Fatal(err)
		}
		t.Log("NAT ready")
		time.Sleep(90 * time.Second)
	case "client":
		for _, proto := range []string{"tcp4", "udp4"} {
			c, err := net.DialTimeout(proto, "172.29.228.3:39642", 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("linknest-kernel-"), 200)
			for i := 0; i < 200; i++ {
				if _, err := c.Write(payload); err != nil {
					t.Fatal(proto, err)
				}
				read := make([]byte, len(payload))
				if _, err := io.ReadFull(c, read); err != nil {
					t.Fatal(proto, err)
				}
				if !bytes.Equal(read, payload) {
					t.Fatal("changed payload")
				}
			}
			c.Close()
			t.Log(proto, "200 packets/blocks passed")
		}
	case "blocked":
		c, err := net.DialTimeout("udp4", "172.29.228.3:39642", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("blocked"))
		_, err = c.Read(make([]byte, 32))
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Fatal("blacklist did not drop", err)
		}
	case "wrong-port":
		c, err := net.DialTimeout("tcp4", "172.29.228.3:39643", time.Second)
		if err == nil {
			c.Close()
			t.Fatal("unrelated port forwarded")
		}
	default:
		t.Fatal("unknown fixture role")
	}
}
