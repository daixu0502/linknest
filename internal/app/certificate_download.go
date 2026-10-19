package app

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

var errCertificateBundle = errors.New("证书或私钥损坏，无法下载")

func (c *CertManager) archive(id string) ([]byte, error) {
	if !validID.MatchString(id) {
		return nil, errors.New("证书标识无效")
	}
	// Read one atomic bundle so renewal cannot mix an old key with a new chain.
	c.mu.Lock()
	bundle, err := os.ReadFile(filepath.Join(c.store.dir, "certificates", id+".pem"))
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var chain, key []byte
	for len(bundle) > 0 {
		block, rest := pem.Decode(bundle)
		if block == nil {
			break
		}
		bundle = rest
		switch block.Type {
		case "CERTIFICATE":
			chain = append(chain, pem.EncodeToMemory(block)...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if len(key) != 0 {
				return nil, errCertificateBundle
			}
			key = pem.EncodeToMemory(block)
		}
	}
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		return nil, errCertificateBundle
	}
	// Only certificate material is exported; renewal credentials and ACME account
	// keys stay on the server. Build in memory without leaving a private-key ZIP.
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, file := range []struct {
		name string
		data []byte
	}{{"fullchain.pem", chain}, {"privkey.pem", key}} {
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.SetMode(0600)
		entry, err := zw.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := entry.Write(file.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (a *App) downloadCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var q struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &q) {
		return
	}
	if !validID.MatchString(q.ID) {
		fail(w, http.StatusBadRequest, "证书标识无效")
		return
	}
	data, err := a.certs.archive(q.ID)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			fail(w, http.StatusNotFound, "证书不存在或尚未签发")
		case errors.Is(err, errCertificateBundle):
			fail(w, http.StatusBadRequest, errCertificateBundle.Error())
		default:
			fail(w, http.StatusInternalServerError, "证书打包失败，请检查证书文件是否可读")
		}
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="linknest-`+q.ID+`.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}
