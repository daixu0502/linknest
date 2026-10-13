package app

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIconCachePersistenceAndValidation(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	var data bytes.Buffer
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	img.Set(0, 0, color.NRGBA{R: 255, A: 255})
	png.Encode(&data, img)
	upload := func(b []byte, cookie *http.Cookie, csrf bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/icons/upload", bytes.NewReader(b))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf {
			r.Header.Set("X-LinkNest-Request", "1")
		}
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		return w
	}
	if upload(data.Bytes(), nil, true).Code != 401 || upload(data.Bytes(), ck, false).Code != 403 {
		t.Fatal("icon auth/CSRF bypass")
	}
	for _, bad := range [][]byte{[]byte(`<svg onload="alert(1)"/>`), []byte("not png")} {
		if upload(bad, ck, true).Code != 400 {
			t.Fatal("active/non-image accepted")
		}
	}
	if upload(make([]byte, (512<<10)+1), ck, true).Code != 413 {
		t.Fatal("oversize accepted")
	}
	var big bytes.Buffer
	png.Encode(&big, image.NewNRGBA(image.Rect(0, 0, 257, 1)))
	if upload(big.Bytes(), ck, true).Code != 400 {
		t.Fatal("oversize dimensions accepted")
	}
	w := upload(data.Bytes(), ck, true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var saved struct {
		URL string `json:"url"`
	}
	json.Unmarshal(w.Body.Bytes(), &saved)
	if !localIconURL(saved.URL) {
		t.Fatal("invalid local path", saved.URL)
	}
	if upload(data.Bytes(), ck, true).Body.String() != w.Body.String() {
		t.Fatal("not deduplicated")
	}
	entries, _ := os.ReadDir(filepath.Join(a.store.dir, "icons"))
	if len(entries) != 1 {
		t.Fatal("duplicate files")
	}
	c := a.store.snapshot()
	c.Bookmarks = []Bookmark{{ID: "icon-test", Name: "test", URL: "https://example.com", Icon: saved.URL}}
	if err := validatePanel(c); err != nil {
		t.Fatal(err)
	}
	// A new handler/portal reads the persistent file without any remote requests.
	for _, portal := range []bool{false, true} {
		r := httptest.NewRequest("GET", saved.URL, nil)
		out := httptest.NewRecorder()
		if portal {
			newPortal(a.store, func(string, string) {}).serve(WebRoute{Backend: "bookmarks", PublicAccess: true}, out, r)
		} else {
			a.handler().ServeHTTP(out, r)
		}
		if out.Code != 200 || out.Header().Get("Content-Type") != "image/png" || !strings.Contains(out.Header().Get("Cache-Control"), "immutable") {
			t.Fatal(out.Code, out.Header())
		}
		if _, err := png.Decode(bytes.NewReader(out.Body.Bytes())); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{iconPrefix, iconPrefix + "../auth.json", iconPrefix + strings.Repeat("a", 64) + ".svg", iconPrefix + strings.Repeat("A", 64) + ".png"} {
		if localIconURL(path) {
			t.Fatal("unsafe path accepted")
		}
		out := httptest.NewRecorder()
		serveCachedIcon(a.store.dir, out, httptest.NewRequest("GET", path, nil))
		if out.Code != 404 {
			t.Fatal(path, out.Code)
		}
	}
}

func TestAccountChange(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	oldHash := a.auth.PasswordHash
	q := map[string]string{"username": "new-admin", "currentPassword": "wrong"}
	if request(a, "POST", "/api/account", q, ck).Code != 403 {
		t.Fatal("wrong password accepted")
	}
	q["currentPassword"] = "test-password-12345"
	if w := request(a, "POST", "/api/account", q, ck); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if a.auth.PasswordHash != oldHash || a.auth.Username != "new-admin" {
		t.Fatal("username-only changed password")
	}
	if request(a, "GET", "/api/state", nil, ck).Code != 401 {
		t.Fatal("old session valid")
	}
	if request(a, "POST", "/api/login", map[string]string{"username": "admin", "password": "test-password-12345"}, nil).Code != 401 {
		t.Fatal("old username works")
	}
	w := request(a, "POST", "/api/login", map[string]string{"username": "new-admin", "password": "test-password-12345"}, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	ck = w.Result().Cookies()[0]
	q["newPassword"] = "updated-test-password-12345"
	if request(a, "POST", "/api/account", q, ck).Code != 200 || a.auth.PasswordHash == oldHash {
		t.Fatal("new password failed")
	}
	if request(a, "POST", "/api/login", map[string]string{"username": "new-admin", "password": q["newPassword"]}, nil).Code != 200 {
		t.Fatal("new login failed")
	}
}

func TestPanelPreferences(t *testing.T) {
	a := testApp(t)
	c := a.store.snapshot()
	c.Bookmarks = []Bookmark{{ID: "test", Name: "test", URL: "https://example.com", URLs: []string{"https://example.com"}, InternalURLs: []string{"http://192.168.1.2", "https://example.com"}}}
	for mode, want := range map[string]int{"external": 1, "internal": 2, "mixed": 2, "auto": 2} {
		groups := panelGroupsForNetwork(c, "192.168.1.3:5000", mode)
		if len(groups[0].Links[0].URLs) != want {
			t.Fatal(mode, groups)
		}
	}
	c.Panel.IconSources = []IconSource{}
	b, _ := json.Marshal(c)
	var round Config
	json.Unmarshal(b, &round)
	if round.Panel.IconSources == nil {
		t.Fatal("empty source list became default")
	}
	for _, bg := range []string{"aurora", "sunset", "ocean", "forest", "dusk", "slate", "mist"} {
		c.Panel.BackgroundPreset = bg
		if err := validatePanel(c); err != nil {
			t.Fatal(err)
		}
	}
	c.Panel.BackgroundPreset = "bad"
	if validatePanel(c) == nil {
		t.Fatal("invalid background")
	}
	c.Panel.BackgroundPreset = ""
	for _, source := range []IconSource{{ID: "x", Name: "x", Kind: "json", URL: "http://example.com"}, {ID: "x", Name: "x", Kind: "evil", URL: "https://example.com"}, {ID: "x", Name: "x", Kind: "json", URL: "https://example.com/?secret=x"}} {
		c.Panel.IconSources = []IconSource{source}
		if validatePanel(c) == nil {
			t.Fatal("unsafe source")
		}
	}
	c.Panel.IconSources = nil
	a.store.mu.Lock()
	a.store.cfg = c
	a.store.mu.Unlock()
	p := newPortal(a.store, func(string, string) {})
	for _, mode := range []string{"internal", "mixed"} {
		w := httptest.NewRecorder()
		p.serve(WebRoute{ID: "test", Backend: "bookmarks", AccessPassword: "not-logged-in"}, w, httptest.NewRequest("GET", "/?network="+mode, nil))
		if strings.Contains(w.Body.String(), "192.168.1.2") {
			t.Fatal("unauthenticated link leak")
		}
	}
}
