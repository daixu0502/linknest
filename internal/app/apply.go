package app

import "time"

type ApplyStatus struct {
	State           string `json:"state"`
	Revision        string `json:"revision"`
	AppliedRevision string `json:"appliedRevision"`
	Message         string `json:"message"`
	Updated         string `json:"updated"`
}

// One finite worker drains/coalesces changes without holding the writer lock.
func (a *App) queueApply() {
	_, revision := a.store.snapshotRevision()
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if a.applyClosed {
		return
	}
	a.applySequence++
	a.applyStatus.State, a.applyStatus.Revision = "pending", revision
	a.applyStatus.Message = "配置已保存，等待应用"
	if a.applyRunning {
		return
	}
	a.applyRunning = true
	a.applyWG.Add(1)
	go func() {
		defer a.applyWG.Done()
		for {
			a.applyMu.Lock()
			if a.applyClosed {
				a.applyRunning = false
				a.applyMu.Unlock()
				return
			}
			sequence := a.applySequence
			a.applyMu.Unlock()
			cfg, revision := a.store.snapshotRevision()
			a.engine.apply(cfg)
			result := ApplyStatus{State: "applied", Revision: revision, AppliedRevision: revision, Message: "配置已应用；后端连通性需单独检查", Updated: time.Now().Format(time.RFC3339)}
			for _, r := range a.engine.statuses() {
				if r.State == "error" || r.Firewall.State == "error" {
					result.State = "error"
					result.Message = "配置已保存，部分规则应用失败，请查看规则详情"
					break
				}
			}
			a.applyMu.Lock()
			if sequence != a.applySequence {
				a.applyMu.Unlock()
				continue
			}
			if result.State == "error" {
				result.AppliedRevision = a.applyStatus.AppliedRevision
			}
			a.applyStatus = result
			a.applyRunning = false
			a.applyMu.Unlock()
			return
		}
	}()
}
func (a *App) applicationStatus() ApplyStatus {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	return a.applyStatus
}
func (a *App) closeApply() {
	a.applyMu.Lock()
	a.applyClosed = true
	a.applyMu.Unlock()
	a.applyWG.Wait()
}
