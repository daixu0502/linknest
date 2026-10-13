package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type CertStep struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
	Time    string `json:"time"`
}
type CertJobStatus struct {
	ID      string     `json:"id"`
	State   string     `json:"state"`
	Stage   string     `json:"stage"`
	Message string     `json:"message"`
	Started string     `json:"started"`
	Updated string     `json:"updated"`
	Steps   []CertStep `json:"steps"`
}

func (c *CertManager) persistJobsLocked() {
	b, err := json.Marshal(c.states)
	if err == nil {
		err = writeAtomic(filepath.Join(c.store.dir, "certificate-jobs.json"), b)
	}
	if err != nil {
		c.log("warning", "证书过程日志无法保存到数据卷")
	}
}
func (c *CertManager) loadJobs() {
	b, err := os.ReadFile(filepath.Join(c.store.dir, "certificate-jobs.json"))
	if err != nil {
		return
	}
	if json.Unmarshal(b, &c.states) != nil || c.states == nil {
		c.states = map[string]CertJobStatus{}
		return
	}
	for id, s := range c.states {
		if s.State == "running" {
			s.State = "error"
			s.Message = "上次申请因服务退出而中断，请查看 DNS 临时记录后手动重试"
			s.Updated = time.Now().Format(time.RFC3339)
			c.states[id] = s
		}
	}
}
func (c *CertManager) progress(id, stage, message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.states[id]
	now := time.Now().Format(time.RFC3339)
	if s.Started == "" {
		s.Started = now
	}
	s.ID = id
	s.State = "running"
	s.Updated = now
	if s.Stage != stage || s.Message != message {
		s.Steps = append(s.Steps, CertStep{Stage: stage, Message: message, Time: now})
		if len(s.Steps) > 100 {
			s.Steps = s.Steps[len(s.Steps)-100:]
		}
	}
	s.Stage = stage
	s.Message = message
	c.states[id] = s
	c.persistJobsLocked()
}
func (c *CertManager) finish(id string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.states[id]
	s.State = "success"
	s.Message = "证书已保存；TLS 新连接自动使用新证书"
	if err != nil {
		s.State = "error"
		s.Message = err.Error()
	}
	s.Updated = time.Now().Format(time.RFC3339)
	s.Steps = append(s.Steps, CertStep{Stage: s.Stage, Message: s.Message, Time: s.Updated})
	if len(s.Steps) > 100 {
		s.Steps = s.Steps[len(s.Steps)-100:]
	}
	c.states[id] = s
	delete(c.busy, id)
	c.persistJobsLocked()
	c.log(s.State, "证书 "+id+"："+s.Message)
}
func (c *CertManager) note(id, stage, message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.states[id]
	s.Updated = time.Now().Format(time.RFC3339)
	s.Steps = append(s.Steps, CertStep{Stage: stage, Message: message, Time: s.Updated})
	if len(s.Steps) > 100 {
		s.Steps = s.Steps[len(s.Steps)-100:]
	}
	c.states[id] = s
	c.persistJobsLocked()
}
func (c *CertManager) task(id string) (CertRequest, error) {
	var r CertRequest
	if !validID.MatchString(id) {
		return r, errors.New("证书标识无效")
	}
	b, e := os.ReadFile(filepath.Join(c.store.dir, "certificates", id+".renew.json"))
	if e != nil {
		return r, errors.New("证书申请任务不存在；手动导入的证书不能续期")
	}
	if json.Unmarshal(b, &r) != nil {
		return r, errors.New("证书任务配置损坏")
	}
	return r, nil
}
func (c *CertManager) tasks() []CertRequest {
	paths, _ := filepath.Glob(filepath.Join(c.store.dir, "certificates", "*.renew.json"))
	out := []CertRequest{}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		var r CertRequest
		if e == nil && json.Unmarshal(b, &r) == nil {
			r.SecretSet = r.Account.Secret != ""
			r.Account.Secret = ""
			out = append(out, normalizeCertRequest(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Called with c.mu held. Empty credentials retain only this task's account.
func (c *CertManager) saveTaskLocked(r CertRequest) (CertRequest, error) {
	r = normalizeCertRequest(r)
	if e := validateCertRequest(r); e != nil {
		return r, e
	}
	old, e := c.task(r.ID)
	if e != nil && len(c.tasks()) >= 64 {
		return r, errors.New("证书任务最多 64 个")
	}
	if r.Account.AccessKeyID == "" {
		r.Account.AccessKeyID = old.Account.AccessKeyID
	}
	if r.Account.Secret == "" {
		if r.Account.AccessKeyID != old.Account.AccessKeyID || old.Account.Secret == "" {
			return r, errors.New("请独立填写此证书的阿里云 AccessKey ID 和 Secret")
		}
		r.Account.Secret = old.Account.Secret
	} else {
		r.Account.Secret, e = c.store.seal(r.Account.Secret)
		if e != nil {
			return r, e
		}
	}
	if r.Account.AccessKeyID == "" {
		return r, errors.New("请填写此证书的 AccessKey ID")
	}
	r.SecretSet = false
	b, _ := json.Marshal(r)
	e = writeAtomic(filepath.Join(c.store.dir, "certificates", r.ID+".renew.json"), b)
	return r, e
}
func (c *CertManager) saveTask(r CertRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy[r.ID] {
		return errors.New("证书申请中，暂不能编辑")
	}
	_, e := c.saveTaskLocked(r)
	return e
}
func (c *CertManager) runSaved(id string) error {
	r, e := c.task(id)
	if e != nil {
		return e
	}
	r.Account.Secret, e = c.store.unseal(r.Account.Secret)
	if e != nil {
		return errors.New("证书独立凭据无法读取")
	}
	return c.start(r)
}
func (c *CertManager) remove(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validID.MatchString(id) {
		return errors.New("证书标识无效")
	}
	if c.busy[id] {
		return errors.New("证书申请中，不能删除")
	}
	cfg := c.store.snapshot()
	for _, r := range cfg.Rules {
		if r.Certificate == id {
			return errors.New("证书已被反向代理引用，请先更换或取消引用")
		}
	}
	if cfg.AdminTLS.Certificate == id {
		return errors.New("证书已被管理后台引用，请先更换或取消引用")
	}
	for _, suffix := range []string{".pem", ".renew.json"} {
		e := os.Remove(filepath.Join(c.store.dir, "certificates", id+suffix))
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	delete(c.states, id)
	c.persistJobsLocked()
	return nil
}
