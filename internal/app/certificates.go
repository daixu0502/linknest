package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

type CertInfo struct {
	Source        string   `json:"source"`
	NotBefore     string   `json:"notBefore"`
	ID            string   `json:"id"`
	Domains       []string `json:"domains"`
	Expires       string   `json:"expires"`
	Issuer        string   `json:"issuer"`
	AutoRenew     bool     `json:"autoRenew"`
	Staging       bool     `json:"staging"`
	Error         string   `json:"error,omitempty"`
	Name          string   `json:"name"`
	RemainingDays int      `json:"remainingDays"`
}
type CertRequest struct {
	ID        string     `json:"id"`
	Domain    string     `json:"domain"`
	Zone      string     `json:"zone"`
	Email     string     `json:"email"`
	Staging   bool       `json:"staging"`
	Name      string     `json:"name"`
	Domains   []string   `json:"domains"`
	Account   DNSAccount `json:"account"`
	Disabled  bool       `json:"disabled"`
	SecretSet bool       `json:"secretSet,omitempty"`
}
type CertManager struct {
	queue     []CertRequest
	worker    bool
	nextScan  time.Time
	issueWork func(context.Context, CertRequest) error
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closed    bool
	mu        sync.Mutex
	store     *Store
	busy      map[string]bool
	states    map[string]CertJobStatus
	log       func(string, string)
}

func newCerts(s *Store, log func(string, string)) *CertManager {
	ctx, cancel := context.WithCancel(context.Background())
	c := &CertManager{ctx: ctx, cancel: cancel, store: s, busy: map[string]bool{}, states: map[string]CertJobStatus{}, log: log}
	c.loadJobs()
	return c
}
func (c *CertManager) close() { c.mu.Lock(); c.closed = true; c.cancel(); c.mu.Unlock(); c.wg.Wait() }
func (c *CertManager) status() []CertJobStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []CertJobStatus{}
	for _, s := range c.states {
		s.Steps = append([]CertStep{}, s.Steps...)
		out = append(out, s)
	}
	return out
}
func (c *CertManager) list() []CertInfo {
	out := []CertInfo{}
	paths, _ := filepath.Glob(filepath.Join(c.store.dir, "certificates", "*.pem"))
	for _, p := range paths {
		id := strings.TrimSuffix(filepath.Base(p), ".pem")
		v := CertInfo{ID: id, Source: "unknown"}
		b, _ := os.ReadFile(p)
		block, _ := pem.Decode(b)
		if block == nil {
			v.Error = "证书格式错误"
		} else if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
			v.Error = "证书无法解析"
		} else {
			v.Domains = cert.DNSNames
			v.Expires = cert.NotAfter.Format(time.RFC3339)
			v.Issuer = cert.Issuer.CommonName
			v.NotBefore = cert.NotBefore.Format(time.RFC3339)
			v.Staging = strings.Contains(strings.ToLower(v.Issuer), "staging") || strings.Contains(strings.ToLower(v.Issuer), "fake le")
			v.RemainingDays = int(time.Until(cert.NotAfter).Hours() / 24)
		}
		if _, err := tls.X509KeyPair(b, b); err != nil {
			v.Error = "证书与私钥不匹配或损坏"
		}
		for rest := b; len(rest) > 0; {
			block, next := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = next
			if block.Type == "LINKNEST CERTIFICATE METADATA" {
				var meta certificateOrigin
				if json.Unmarshal(block.Bytes, &meta) == nil {
					v.Source = meta.Source
					v.Staging = meta.Staging
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(c.store.dir, "certificates", id+".renew.json")); err == nil {
			var req CertRequest
			if json.Unmarshal(b, &req) == nil {
				v.AutoRenew = !req.Disabled
				v.Name = req.Name
			}
		}
		out = append(out, v)
	}
	return out
}

type certificateOrigin struct {
	Source  string `json:"source"`
	Staging bool   `json:"staging"`
}

func (c *CertManager) savePair(id string, cert, key []byte) error {
	return c.savePairOrigin(id, cert, key, certificateOrigin{Source: "imported"})
}
func (c *CertManager) savePairOrigin(id string, cert, key []byte, origin certificateOrigin) error {
	if !validID.MatchString(id) {
		return errors.New("证书 ID 无效")
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return errors.New("证书和私钥格式错误或不匹配")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) {
		return errors.New("证书已过期或无效")
	}
	p := filepath.Join(c.store.dir, "certificates", id)
	// One atomic replacement prevents concurrent handshakes from seeing a mismatched pair.
	bundle := append(append(append([]byte{}, cert...), '\n'), key...)
	if origin.Source == "imported" {
		issuer := strings.ToLower(leaf.Issuer.CommonName)
		origin.Staging = strings.Contains(issuer, "staging") || strings.Contains(issuer, "fake le")
	}
	metadata, _ := json.Marshal(origin)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "LINKNEST CERTIFICATE METADATA", Bytes: metadata})...)
	return writeAtomic(p+".pem", bundle)
}
func (c *CertManager) importPair(id string, cert, key []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy[id] {
		return errors.New("该证书正在申请中")
	}
	if e := c.savePair(id, cert, key); e != nil {
		return e
	}
	p := filepath.Join(c.store.dir, "certificates", id+".renew.json")
	if e := os.Remove(p); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}
func validateCertRequest(r CertRequest) error {
	r = normalizeCertRequest(r)
	if !validID.MatchString(r.ID) || len(r.Domains) == 0 || len(r.Domains) > 20 || !domainRE.MatchString(r.Zone) || strings.HasPrefix(r.Zone, "*.") {
		return errors.New("证书 ID 或域名格式错误")
	}
	for _, domain := range r.Domains {
		name := strings.TrimPrefix(domain, "*.")
		if !domainRE.MatchString(domain) || (name != r.Zone && !strings.HasSuffix(name, "."+r.Zone)) {
			return errors.New("证书域名无效或不属于填写的 DNS 主域名")
		}
	}
	if !strings.Contains(r.Email, "@") || strings.ContainsAny(r.Email, "\r\n ") {
		return errors.New("请填写有效联系邮箱")
	}
	return nil
}
func normalizeCertRequest(r CertRequest) CertRequest {
	if len(r.Domains) == 0 && r.Domain != "" {
		r.Domains = []string{r.Domain}
	}
	clean := []string{}
	seen := map[string]bool{}
	for _, name := range r.Domains {
		name = strings.ToLower(strings.TrimSpace(name))
		if !seen[name] {
			clean = append(clean, name)
			seen[name] = true
		}
	}
	r.Domains = clean
	r.Domain = ""
	if r.Name == "" {
		r.Name = r.ID
	}
	return r
}
func challengeName(r CertRequest, identifier string) (string, string, error) {
	r = normalizeCertRequest(r)
	identifier = strings.TrimPrefix(identifier, "*.")
	allowed := false
	for _, d := range r.Domains {
		if strings.TrimPrefix(d, "*.") == identifier {
			allowed = true
		}
	}
	if !allowed {
		return "", "", errors.New("ACME 返回了不属于本次申请的验证域名")
	}
	fqdn := "_acme-challenge." + identifier
	return fqdn, strings.TrimSuffix(fqdn, "."+r.Zone), nil
}
func (c *CertManager) start(r CertRequest) error {
	r = normalizeCertRequest(r)
	if e := validateCertRequest(r); e != nil {
		return e
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("服务正在停止")
	}
	if c.busy[r.ID] {
		c.mu.Unlock()
		return errors.New("证书任务已在运行")
	}
	var err error
	r, err = c.saveTaskLocked(r)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.busy[r.ID] = true
	previous := c.states[r.ID]
	c.states[r.ID] = CertJobStatus{ID: r.ID, State: "queued", Stage: "prepare", Message: "已加入申请队列", Updated: time.Now().Format(time.RFC3339), Steps: []CertStep{}, Failures: previous.Failures}
	c.queue = append(c.queue, r)
	c.persistJobsLocked()
	if !c.worker {
		c.worker = true
		c.wg.Add(1)
		go c.runQueue()
	}
	c.mu.Unlock()
	return nil
}
func (c *CertManager) runQueue() {
	defer c.wg.Done()
	for {
		c.mu.Lock()
		if c.closed || len(c.queue) == 0 {
			c.worker = false
			c.mu.Unlock()
			return
		}
		r := c.queue[0]
		c.queue = c.queue[1:]
		c.mu.Unlock()
		c.progress(r.ID, "prepare", "正在申请")
		ctx, cancel := context.WithTimeout(c.ctx, 15*time.Minute)
		work := c.issueWork
		if work == nil {
			work = c.issue
		}
		err := work(ctx, r)
		cancel()
		c.finish(r.ID, err)
	}
}

func (c *CertManager) issue(ctx context.Context, r CertRequest) error {
	r = normalizeCertRequest(r)
	c.progress(r.ID, "prepare", "准备独立证书凭据与 ACME 账户")
	account := r.Account
	secret, err := c.store.unseal(account.Secret)
	if err != nil {
		return err
	}
	dns := AliDNS{ID: account.AccessKeyID, Secret: secret}
	accountName := "acme-production.key"
	directory := acme.LetsEncryptURL
	if r.Staging {
		directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
		accountName = "acme-staging.key"
	}
	accountPath := filepath.Join(c.store.dir, "certificates", accountName)
	var key *ecdsa.PrivateKey
	if b, e := os.ReadFile(accountPath); e == nil {
		p, _ := pem.Decode(b)
		if p == nil {
			return errors.New("ACME 账户密钥损坏")
		}
		key, e = x509.ParseECPrivateKey(p.Bytes)
		if e != nil {
			return errors.New("ACME 账户密钥格式错误")
		}
	} else if errors.Is(e, os.ErrNotExist) {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, _ := x509.MarshalECPrivateKey(key)
		if err = writeAtomic(accountPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
			return err
		}
	} else {
		return e
	}
	client := &acme.Client{Key: key, DirectoryURL: directory, UserAgent: "LinkNest/" + version}
	c.progress(r.ID, "account", "连接 Let’s Encrypt 并注册 / 读取账户")
	if _, err = client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + r.Email}}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("ACME 账户注册失败：%w", err)
	}
	c.progress(r.ID, "order", "创建证书订单")
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(r.Domains...))
	if err != nil {
		return fmt.Errorf("ACME 创建订单失败：%w", err)
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return err
		}
		if auth.Status == acme.StatusValid {
			c.progress(r.ID, "validation", auth.Identifier.Value+" 已有有效授权")
			continue
		}
		var challenge *acme.Challenge
		for _, x := range auth.Challenges {
			if x.Type == "dns-01" {
				challenge = x
				break
			}
		}
		if challenge == nil {
			return errors.New("ACME 没有提供 DNS-01 验证")
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return err
		}
		fqdn, rr, err := challengeName(r, auth.Identifier.Value)
		if err != nil {
			return err
		}
		c.progress(r.ID, "dns_create", "创建临时 TXT："+fqdn)
		created, err := dns.call(ctx, "AddDomainRecord", map[string]string{"DomainName": r.Zone, "RR": rr, "Type": "TXT", "Value": value, "TTL": "600"})
		if err != nil {
			return err
		}
		if created.RecordID == "" {
			return errors.New("DNS API 未返回新记录 ID")
		}
		// Delete only the exact TXT record created by this request; keep all existing records intact.
		defer func(id string) {
			cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if _, e := dns.call(cleanup, "DeleteDomainRecord", map[string]string{"RecordId": id}); e != nil {
				c.log("warning", "ACME 临时 TXT 清理失败，请在 DNS 控制台核对记录")
				c.note(r.ID, "cleanup", "临时 TXT 清理失败，请在阿里云核对本次记录")
			} else {
				c.note(r.ID, "cleanup", "本次临时 TXT 记录已清理")
			}
		}(created.RecordID)
		if err = c.waitDNS(ctx, r.ID, r.Zone, fqdn, value); err != nil {
			return err
		}
		c.progress(r.ID, "validation", "TXT 已可查询，请求 CA 验证："+auth.Identifier.Value)
		if _, err = client.Accept(ctx, challenge); err != nil {
			return err
		}
		if _, err = client.WaitAuthorization(ctx, authURL); err != nil {
			return fmt.Errorf("DNS 验证失败：%w", err)
		}
	}
	c.progress(r.ID, "signing", "全部域名验证完成，等待签发证书")
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return err
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: r.Domains[0]}, DNSNames: r.Domains}, certKey)
	if err != nil {
		return err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return err
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, _ := x509.MarshalECPrivateKey(certKey)
	c.progress(r.ID, "save", "校验证书与私钥，保存证书文件")
	if err = c.savePairOrigin(r.ID, certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), certificateOrigin{Source: "acme", Staging: r.Staging}); err != nil {
		return err
	}
	return nil
}
func (c *CertManager) tickRenewals() {
	c.mu.Lock()
	due := c.nextScan.IsZero() || !time.Now().Before(c.nextScan)
	if !due {
		for id, s := range c.states {
			next, e := time.Parse(time.RFC3339, s.RetryAt)
			if e == nil && !time.Now().Before(next) && !c.busy[id] {
				due = true
				break
			}
		}
	}
	c.mu.Unlock()
	if due {
		c.renew()
	}
}
func (c *CertManager) renew() {
	c.mu.Lock()
	c.nextScan = time.Now().Add(12 * time.Hour)
	c.mu.Unlock()
	list := c.list()
	sort.SliceStable(list, func(i, j int) bool { return list[i].Expires < list[j].Expires })
	for _, i := range list {
		c.mu.Lock()
		job := c.states[i.ID]
		busy := c.busy[i.ID]
		c.mu.Unlock()
		if next, e := time.Parse(time.RFC3339, job.RetryAt); busy || e == nil && time.Now().Before(next) {
			continue
		}
		if !i.AutoRenew || i.Error != "" {
			continue
		}
		t, e := time.Parse(time.RFC3339, i.Expires)
		if e != nil || time.Until(t) > 30*24*time.Hour {
			continue
		}
		b, e := os.ReadFile(filepath.Join(c.store.dir, "certificates", i.ID+".renew.json"))
		if e != nil {
			continue
		}
		var r CertRequest
		if json.Unmarshal(b, &r) == nil {
			// Preserve renewal of pre-0.2 certificates; new applications always
			// require their own account and persist it independently.
			if r.Account.AccessKeyID == "" {
				r.Account, e = c.store.dnsAccount("")
			} else {
				r.Account.Secret, e = c.store.unseal(r.Account.Secret)
			}
			if e != nil {
				c.log("error", "证书 "+r.ID+" 续期凭据无法读取")
				continue
			}
			if err := c.start(r); err != nil {
				c.log("error", "证书 "+r.ID+" 无法加入续期队列："+err.Error())
			}
		}
	}
}
