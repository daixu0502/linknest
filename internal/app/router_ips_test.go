package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func waitRouterIPs(t *testing.T, cache *routerIPCache) routerAddresses {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		cache.mu.Lock()
		value, running := cache.value, cache.running
		cache.mu.Unlock()
		if !running {
			return value
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("IP refresh did not complete")
	return routerAddresses{}
}
func TestRouterIPCacheNonBlockingAndCooldown(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	cache := &routerIPCache{detect: func(ctx context.Context, v6 bool) (string, error) {
		calls.Add(1)
		select {
		case <-gate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		if v6 {
			return "2606:4700::1111", nil
		}
		return "1.1.1.1", nil
	}}
	now := time.Now()
	first := cache.snapshotAt(now)
	if !first.IPv4.Loading || !first.IPv6.Loading {
		t.Fatal("first read should return loading without waiting")
	}
	for i := 0; i < 50; i++ {
		cache.snapshotAt(now)
	}
	close(gate)
	value := waitRouterIPs(t, cache)
	if calls.Load() != 2 || value.IPv4.Value != "1.1.1.1" || value.IPv6.Value != "2606:4700::1111" || value.IPv4.Updated == "" {
		t.Fatalf("unexpected snapshot: %+v, calls %d", value, calls.Load())
	}
	cache.snapshotAt(now.Add(59 * time.Second))
	if calls.Load() != 2 {
		t.Fatal("snapshot refreshed inside cooldown")
	}
	cache.snapshotAt(now.Add(time.Minute))
	waitRouterIPs(t, cache)
	if calls.Load() != 4 {
		t.Fatal("did not refresh expired cache")
	}
}
func TestRouterIPCacheIndependentFailureAndLastValue(t *testing.T) {
	cache := &routerIPCache{value: routerAddresses{IPv6: routerAddress{Value: "2606:4700::1111", Updated: "old"}}, detect: func(ctx context.Context, v6 bool) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("refresh context needs deadline")
		}
		if v6 {
			return "", errors.New("IPv6 unreachable")
		}
		return "8.8.8.8", nil
	}}
	cache.snapshotAt(time.Now())
	value := waitRouterIPs(t, cache)
	if value.IPv4.Value != "8.8.8.8" || value.IPv4.Error != "" || value.IPv6.Value != "2606:4700::1111" || value.IPv6.Error != "IPv6 unreachable" || value.IPv6.Loading {
		t.Fatalf("unexpected failure snapshot: %+v", value)
	}
}
