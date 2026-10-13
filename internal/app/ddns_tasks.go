package app

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
)

type RecordStatus struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Message string `json:"message"`
	Value   string `json:"value"`
	Zone    string `json:"zone,omitempty"`
}
type DNSManager struct {
	mu       sync.Mutex
	store    *Store
	states   map[string]JobStatus
	running  map[string]bool
	deleting map[string]bool
	pending  map[string]*DDNSRule
	cancels  map[string]context.CancelFunc
	due      map[string]time.Time
	log      func(string, string)
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	closed   bool
	detect   func(context.Context, IPSource, bool) (string, error)
	client   func(DNSAccount) AliDNS
}

func newDNS(s *Store, log func(string, string)) *DNSManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &DNSManager{store: s, states: map[string]JobStatus{}, running: map[string]bool{}, pending: map[string]*DDNSRule{}, cancels: map[string]context.CancelFunc{}, due: map[string]time.Time{}, log: log, ctx: ctx, cancel: cancel, detect: detectIP, client: func(a DNSAccount) AliDNS { return AliDNS{ID: a.AccessKeyID, Secret: a.Secret} }}
}
func (d *DNSManager) close() { d.mu.Lock(); d.closed = true; d.cancel(); d.mu.Unlock(); d.wg.Wait() }
func (d *DNSManager) status() []JobStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []JobStatus{}
	for _, s := range d.states {
		out = append(out, s)
	}
	return out
}
func (d *DNSManager) tick(now time.Time) {
	tasks := d.store.snapshot().DDNS
	due := []DDNSRule{}
	present := map[string]bool{}
	d.mu.Lock()
	for _, r := range tasks {
		present[r.ID] = true
		if !r.Enabled {
			delete(d.due, r.ID)
			if st, ok := d.states[r.ID]; ok {
				st.Next = ""
				d.states[r.ID] = st
			}
			continue
		}
		next, ok := d.due[r.ID]
		if !ok {
			next = now.Add(time.Duration(r.StartDelay) * time.Second)
			d.due[r.ID] = next
			d.states[r.ID] = JobStatus{ID: r.ID, State: "waiting", Message: "等待首次检查", Next: next.Format(time.RFC3339)}
		}
		if !now.Before(next) && !d.running[r.ID] {
			due = append(due, r)
		}
	}
	for id := range d.due {
		if !present[id] {
			delete(d.due, id)
			delete(d.states, id)
		}
	}
	d.mu.Unlock()
	for _, r := range due {
		// A save may have disabled/deleted the task after the scheduling snapshot.
		d.mu.Lock()
		for _, current := range d.store.snapshot().DDNS {
			if current.ID == r.ID && current.Enabled {
				d.startLocked(current)
				break
			}
		}
		d.mu.Unlock()
	}
}
func (d *DNSManager) start(r DDNSRule) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.startLocked(r)
}
func (d *DNSManager) startLocked(r DDNSRule) bool {
	if d.closed || d.running[r.ID] || d.deleting[r.ID] {
		return false
	}
	d.running[r.ID] = true
	d.wg.Add(1)
	old := d.states[r.ID]
	old.ID = r.ID
	old.State = "running"
	old.Message = "正在检查 IP 与 DNS 记录"
	d.states[r.ID] = old
	go func() {
		defer d.wg.Done()
		for {
			ctx, cancel := context.WithTimeout(d.ctx, 3*time.Minute)
			d.mu.Lock()
			d.cancels[r.ID] = cancel
			if _, pending := d.pending[r.ID]; pending {
				cancel()
			}
			d.mu.Unlock()
			st := d.updateTask(ctx, r)
			cancel()
			now := time.Now()
			st.Updated = now.Format(time.RFC3339)
			d.mu.Lock()
			delete(d.cancels, r.ID)
			if next, dirty := d.pending[r.ID]; dirty {
				delete(d.pending, r.ID)
				if next != nil && !d.closed {
					r = *next
					d.states[r.ID] = JobStatus{ID: r.ID, State: "running", Message: "配置已变更，正在同步最新记录"}
					d.mu.Unlock()
					continue
				}
				delete(d.running, r.ID)
				delete(d.due, r.ID)
				delete(d.states, r.ID)
				d.mu.Unlock()
				return
			}
			delete(d.running, r.ID)
			interval := r.Interval
			if interval < 60 {
				interval = 300
			}
			d.due[r.ID] = now.Add(time.Duration(interval) * time.Second)
			if r.Enabled {
				st.Next = d.due[r.ID].Format(time.RFC3339)
			}
			d.states[r.ID] = st
			d.mu.Unlock()
			d.log(st.State, "DDNS "+r.Name+"："+st.Message)
			return
		}
	}()
	return true
}

// The config writer holds updateMu while reserved; other tasks remain runnable.
// Refuse a concurrent update instead of cancelling an in-flight provider write.
func (d *DNSManager) reserveDelete(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.running[id] || d.deleting[id] {
		return false
	}
	if d.deleting == nil {
		d.deleting = map[string]bool{}
	}
	d.deleting[id] = true
	return true
}
func (d *DNSManager) releaseDelete(id string) {
	d.mu.Lock()
	delete(d.deleting, id)
	d.mu.Unlock()
}

func dnsEffectiveRecords(r DDNSRule) []DDNSRecord {
	out := []DDNSRecord{}
	for _, rec := range r.Records {
		if rec.Enabled {
			rec.Name = ""
			if rec.Value != "{ipv4Addr}" && rec.Value != "{ipv6Addr}" {
				rec.Source = IPSource{}
			}
			out = append(out, rec)
		}
	}
	return out
}

// Called only after a successful save, with secrets already retained/encrypted.
func (d *DNSManager) configChanged(before, after Config) {
	old := map[string]DDNSRule{}
	for _, r := range before.DDNS {
		old[r.ID] = r
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range after.DDNS {
		prev, existed := old[r.ID]
		delete(old, r.ID)
		oldAccount, _ := taskAccount(before, r.ID)
		newAccount, _ := taskAccount(after, r.ID)
		changed := !existed || !prev.Enabled || !reflect.DeepEqual(dnsEffectiveRecords(prev), dnsEffectiveRecords(r)) || oldAccount != newAccount
		if !r.Enabled || len(dnsEffectiveRecords(r)) == 0 {
			if d.running[r.ID] {
				d.pending[r.ID] = nil
				if cancel := d.cancels[r.ID]; cancel != nil {
					cancel()
				}
			}
			delete(d.due, r.ID)
			delete(d.states, r.ID)
			continue
		}
		if !changed {
			continue
		}
		if d.running[r.ID] {
			copy := r
			d.pending[r.ID] = &copy
			if cancel := d.cancels[r.ID]; cancel != nil {
				cancel()
			}
			continue
		}
		d.startLocked(r)
	}
	for id := range old {
		if d.running[id] {
			d.pending[id] = nil
			if cancel := d.cancels[id]; cancel != nil {
				cancel()
			}
		}
		delete(d.due, id)
		delete(d.states, id)
	}
}
func (d *DNSManager) updateTask(ctx context.Context, r DDNSRule) JobStatus {
	st := JobStatus{ID: r.ID, State: "success", Records: []RecordStatus{}}
	detected := d.detectRecords(ctx, r, "")
	account, credErr := d.store.dnsAccount(r.ID)
	api := d.client(account)
	var zones []string
	var zoneErr error
	zoneLoaded := false
	failed, ok := 0, 0
	for n, rec := range r.Records {
		rs := RecordStatus{ID: rec.ID, State: "disabled", Message: "已停用"}
		if !rec.Enabled {
			st.Records = append(st.Records, rs)
			continue
		}
		if ctx.Err() != nil {
			st.State = "error"
			st.Message = "更新已取消"
			return st
		}
		value, err := detected[n].Value, error(nil)
		if detected[n].Error != "" {
			err = fmt.Errorf("%s", detected[n].Error)
		}
		if err == nil {
			err = credErr
		}
		if err == nil {
			zone := rec.Zone
			if zone == "" {
				if !zoneLoaded {
					zones, zoneErr = api.zones(ctx)
					zoneLoaded = true
				}
				err = zoneErr
				if err == nil {
					zone, err = matchDNSZone(rec.Domain, zones)
				}
			}
			rs.Zone = zone
			rr := strings.TrimSuffix(rec.Domain, "."+zone)
			if rec.Domain == zone {
				rr = "@"
			}
			var changed bool
			if err == nil {
				changed, err = api.upsertRecord(ctx, zone, rr, rec.Type, value, rec.TTL, rec.Line, rec.Priority)
			}
			rs.Message = "记录已一致，无需修改"
			if changed {
				rs.Message = "已同步到阿里云"
			}
		}
		rs.Value = value
		rs.State = "success"
		if err != nil {
			rs.State = "error"
			rs.Message = err.Error()
			failed++
		} else {
			ok++
		}
		st.Records = append(st.Records, rs)
	}
	st.Message = fmt.Sprintf("%d 条成功，%d 条失败", ok, failed)
	if failed > 0 {
		st.State = "error"
	}
	return st
}

type RecordDetection struct {
	ID     string   `json:"id"`
	Domain string   `json:"domain"`
	Type   string   `json:"type"`
	Source IPSource `json:"source"`
	Value  string   `json:"value"`
	Error  string   `json:"error,omitempty"`
}

// Cache only within this pass and by the entire source plus address family.
// Distinct NICs must never share a task-wide detected address.
func (d *DNSManager) detectRecords(ctx context.Context, task DDNSRule, only string) []RecordDetection {
	type key struct {
		Source IPSource
		V6     bool
	}
	type result struct {
		Value string
		Err   error
	}
	cache := map[key]result{}
	out := []RecordDetection{}
	for _, rec := range task.Records {
		if only != "" && rec.ID != only {
			continue
		}
		r := RecordDetection{ID: rec.ID, Domain: rec.Domain, Type: rec.Type, Source: rec.Source}
		if !rec.Enabled && only == "" {
			out = append(out, r)
			continue
		}
		var err error
		if rec.Value == "{ipv4Addr}" || rec.Value == "{ipv6Addr}" {
			k := key{rec.Source, rec.Value == "{ipv6Addr}"}
			if k.Source.Mode == "" {
				k.Source.Mode = "auto"
			}
			v, found := cache[k]
			if !found {
				v.Value, v.Err = d.detect(ctx, k.Source, k.V6)
				cache[k] = v
			}
			r.Value, err = v.Value, v.Err
		} else {
			r.Value, err = recordValue(rec, "", "")
		}
		if err != nil {
			r.Error = err.Error()
		}
		out = append(out, r)
	}
	return out
}
