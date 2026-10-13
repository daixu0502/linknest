package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type DeviceStatus struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Message string `json:"message"`
	Checked string `json:"checked"`
}

// An unanswered probe is inconclusive: firewalls may drop it even while online.
func checkDevice(ctx context.Context, d Device) DeviceStatus {
	s := DeviceStatus{ID: d.ID, State: "unknown", Checked: time.Now().Format(time.RFC3339)}
	if d.IP == "" {
		s.State = "unconfigured"
		s.Message = "填写设备 IP 后可检测在线状态"
		return s
	}
	if net.ParseIP(d.IP).To4() == nil || d.CheckPort < 0 || d.CheckPort > 65535 {
		s.Message = "在线检测地址或端口无效"
		return s
	}
	ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	if d.CheckPort > 0 {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(d.IP, strconv.Itoa(d.CheckPort)))
		if err == nil {
			conn.Close()
			s.State = "online"
			s.Message = fmt.Sprintf("TCP %d 已响应", d.CheckPort)
		} else {
			s.Message = "TCP 未响应；可能关闭、端口未监听或被防火墙阻止"
		}
	} else {
		err := pingDevice(ctx, d.IP)
		if err == nil {
			s.State = "online"
			s.Message = "收到 Ping 响应"
		} else {
			s.Message = err.Error()
		}
	}
	return s
}
func icmpChecksum(p []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(p); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	if len(p)%2 != 0 {
		sum += uint32(p[len(p)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
func pingDevice(ctx context.Context, ip string) error {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("Ping 不可用，需要 NET_RAW 权限；也可改用 TCP 检测")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	packet := make([]byte, 24)
	packet[0] = 8
	if _, err = rand.Read(packet[4:]); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(packet[2:4], icmpChecksum(packet))
	if _, err = conn.WriteTo(packet, &net.IPAddr{IP: net.ParseIP(ip)}); err != nil {
		return fmt.Errorf("Ping 发送失败，请检查路由或权限")
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("Ping 未响应；可能关闭或禁止 Ping")
		}
		if from.String() == ip && n >= len(packet) && buf[0] == 0 && buf[1] == 0 && bytes.Equal(buf[4:len(packet)], packet[4:]) {
			return nil
		}
	}
}
func (a *App) checkDevices(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &q) {
		return
	}
	select {
	case a.terminalSlots <- struct{}{}:
		defer func() { <-a.terminalSlots }()
	default:
		fail(w, 429, "检测或连接正在进行，请稍后重试")
		return
	}
	devices := a.store.snapshot().Devices
	out := []DeviceStatus{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, d := range devices {
		if q.ID != "" && d.ID != q.ID {
			continue
		}
		slots <- struct{}{}
		wg.Add(1)
		go func(d Device) {
			defer wg.Done()
			defer func() { <-slots }()
			s := checkDevice(r.Context(), d)
			mu.Lock()
			out = append(out, s)
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	if q.ID != "" && len(out) == 0 {
		fail(w, 404, "设备不存在")
		return
	}
	respond(w, 200, map[string]any{"ok": true, "devices": out})
}
