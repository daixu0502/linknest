package app

import (
	"context"
	"sync"
	"time"
)

type routerAddress struct {
	Value   string `json:"value"`
	Error   string `json:"error,omitempty"`
	Updated string `json:"updated,omitempty"`
	Loading bool   `json:"loading"`
}
type routerAddresses struct {
	IPv4 routerAddress `json:"ipv4"`
	IPv6 routerAddress `json:"ipv6"`
}

// /api/state must never wait on an external IP service. One bounded background
// refresh per minute is shared by all sessions and DDNS cards. It writes no DNS.
type routerIPCache struct {
	mu      sync.Mutex
	value   routerAddresses
	next    time.Time
	running bool
	detect  func(context.Context, bool) (string, error)
}

func detectRouterIP(ctx context.Context, v6 bool) (string, error) {
	// Prefer the actual public interface address on a host-network router. When
	// ambiguous or behind NAT, use the existing protocol-specific exit detector.
	if value, err := pickInterface(interfaces(), "", v6); err == nil {
		return value, nil
	}
	return detectIP(ctx, IPSource{Mode: "auto"}, v6)
}

func (c *routerIPCache) snapshot() routerAddresses {
	return c.snapshotAt(time.Now())
}
func (c *routerIPCache) snapshotAt(now time.Time) routerAddresses {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running && !now.Before(c.next) {
		c.running = true
		c.next = now.Add(time.Minute)
		c.value.IPv4.Loading, c.value.IPv6.Loading = true, true
		detect := c.detect
		if detect == nil {
			detect = detectRouterIP
		}
		go c.refresh(detect)
	}
	return c.value
}
func (c *routerIPCache) refresh(detect func(context.Context, bool) (string, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var wait sync.WaitGroup
	for _, v6 := range []bool{false, true} {
		wait.Add(1)
		go func(v6 bool) {
			defer wait.Done()
			value, err := detect(ctx, v6)
			c.mu.Lock()
			defer c.mu.Unlock()
			address := &c.value.IPv4
			if v6 {
				address = &c.value.IPv6
			}
			address.Loading = false
			if err != nil {
				address.Error = err.Error()
				return // Keep the last successful value, explicitly marked stale.
			}
			*address = routerAddress{Value: value, Updated: time.Now().Format(time.RFC3339)}
		}(v6)
	}
	wait.Wait()
	c.mu.Lock()
	c.running = false
	c.mu.Unlock()
}
