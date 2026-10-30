package app

import "sync"

type terminalEntry struct {
	session string
	close   func()
}
type terminalRegistry struct {
	mu      sync.Mutex
	entries map[*terminalEntry]bool
}

func (r *terminalRegistry) add(session string, close func()) func() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = map[*terminalEntry]bool{}
	}
	e := &terminalEntry{session: session, close: close}
	r.entries[e] = true
	return func() { r.mu.Lock(); delete(r.entries, e); r.mu.Unlock() }
}
func (r *terminalRegistry) revoke(session string) {
	r.mu.Lock()
	var closers []func()
	for e := range r.entries {
		if session == "" || e.session == session {
			closers = append(closers, e.close)
			delete(r.entries, e)
		}
	}
	r.mu.Unlock()
	for _, close := range closers {
		close()
	}
}
