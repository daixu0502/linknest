package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const iconPrefix = "/__linknest/icons/"

var localIconPattern = regexp.MustCompile(`^/__linknest/icons/[a-f0-9]{64}\.png$`)

func localIconURL(value string) bool { return localIconPattern.MatchString(value) }

// No remote fetching here: the authenticated browser converts a selected icon
// to PNG. Re-encoding drops metadata and prevents serving active SVG content.
func (a *App) uploadIcon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "仅支持 POST")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, 413, "图标超过 512 KiB")
		return
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 256 || config.Height > 256 {
		fail(w, 400, "图标必须为不超过 256×256 的 PNG")
		return
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		fail(w, 400, "PNG 图标无法解码")
		return
	}
	var encoded bytes.Buffer
	if png.Encode(&encoded, img) != nil {
		fail(w, 500, "图标编码失败")
		return
	}
	sum := sha256.Sum256(encoded.Bytes())
	name := hex.EncodeToString(sum[:]) + ".png"
	dir := filepath.Join(a.store.dir, "icons")
	a.iconMu.Lock()
	defer a.iconMu.Unlock()
	if os.MkdirAll(dir, 0700) != nil {
		fail(w, 500, "无法创建图标缓存目录")
		return
	}
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fail(w, 500, "无法读取图标缓存")
			return
		}
		var size int64
		for _, e := range entries {
			if info, err := e.Info(); err == nil {
				size += info.Size()
			}
		}
		if len(entries) >= 2048 || size+int64(encoded.Len()) > 64<<20 {
			fail(w, 409, "图标缓存已达上限（2048 个或 64 MiB），请先整理数据卷内的无用图标")
			return
		}
		if writeAtomic(path, encoded.Bytes()) != nil {
			fail(w, 500, "保存图标失败")
			return
		}
	} else if err != nil {
		fail(w, 500, "无法读取图标缓存")
		return
	}
	respond(w, 200, map[string]any{"ok": true, "url": iconPrefix + name})
}

// Content-addressed public images contain no account or source credentials.
// Exact names only; never serve a directory or arbitrary files from /data.
func serveCachedIcon(dir string, w http.ResponseWriter, r *http.Request) {
	if !localIconURL(r.URL.Path) || (r.Method != "GET" && r.Method != "HEAD") {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(dir, "icons", strings.TrimPrefix(r.URL.Path, iconPrefix))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeFile(w, r, path)
}
