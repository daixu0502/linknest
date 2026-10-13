package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test.example"}, DNSNames: []string{"test.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	priv, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv})
}
func TestCertificateAtomicImport(t *testing.T) {
	s := testStore(t)
	m := newCerts(s, quiet)
	defer m.close()
	cert, key := testPair(t)
	if e := m.importPair("local", cert, key); e != nil {
		t.Fatal(e)
	}
	_, wrong := testPair(t)
	if e := m.importPair("local", cert, wrong); e == nil {
		t.Fatal("mismatched pair accepted")
	}
	b, _ := os.ReadFile(filepath.Join(s.dir, "certificates", "local.pem"))
	if _, e := tls.X509KeyPair(b, b); e != nil {
		t.Fatal("old pair lost", e)
	}
	if len(m.list()) != 1 || m.list()[0].AutoRenew {
		t.Fatal("incorrect metadata")
	}
	if e := m.importPair("../escape", cert, key); e == nil {
		t.Fatal("path traversal")
	}
}
func TestCertRequestScope(t *testing.T) {
	r := CertRequest{ID: "cert", Domain: "*.example.com", Zone: "example.com", Email: "test@example.com", Staging: true}
	if e := validateCertRequest(r); e != nil {
		t.Fatal(e)
	}
	r.Domain = "notexample.com"
	if validateCertRequest(r) == nil {
		t.Fatal("out-of-zone certificate allowed")
	}
}
