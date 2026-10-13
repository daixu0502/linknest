package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testApp(t *testing.T) *App {
	t.Helper()
	a, e := newApp(t.TempDir(), "127.0.0.1:17880", false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.certs.close(); a.engine.close() })
	return a
}
func request(a *App, method, path string, data any, cookie *http.Cookie) *httptest.ResponseRecorder {
	b, _ := json.Marshal(data)
	r := httptest.NewRequest(method, "http://localhost"+path, bytes.NewReader(b))
	r.Header.Set("X-LinkNest-Request", "1")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	return w
}
func signIn(t *testing.T, a *App) *http.Cookie {
	t.Helper()
	w := request(a, "POST", "/api/setup", map[string]string{"token": a.bootstrap, "username": "admin", "password": "test-password-12345"}, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(a, "POST", "/api/login", map[string]string{"username": "admin", "password": "test-password-12345"}, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	return w.Result().Cookies()[0]
}
func TestAuthenticationAndCSRF(t *testing.T) {
	a := testApp(t)
	if w := request(a, "GET", "/api/state", nil, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(a, "POST", "/api/setup", map[string]string{"token": "wrong", "password": "test-password-12345"}, nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	ck := signIn(t, a)
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	if w := request(a, "GET", "/api/state", nil, ck); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, origin := range []string{"https://evil.example", "http://localhost.evil.example"} {
		r := httptest.NewRequest("PUT", "http://localhost/api/config", strings.NewReader("{}"))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-LinkNest-Request", "1")
		r.AddCookie(ck)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("csrf permitted", origin)
		}
	}
	r := httptest.NewRequest("PUT", "http://localhost/api/config", strings.NewReader("{}"))
	r.AddCookie(ck)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF header permitted")
	}
	c := a.store.snapshot()
	c.DNS.Secret = "sensitive-example"
	if w = request(a, "PUT", "/api/config", c, ck); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, path := range []string{"/api/state", "/api/export"} {
		w = request(a, "GET", path, nil, ck)
		if strings.Contains(w.Body.String(), "sensitive-example") || strings.Contains(w.Body.String(), "enc:") {
			t.Fatal("secret leak", path)
		}
	}
	if w = request(a, "GET", "/api/terminal?id=none", nil, ck); w.Code != 403 {
		t.Fatal("terminal not disabled")
	}
	request(a, "POST", "/api/logout", nil, ck)
	if w = request(a, "GET", "/api/state", nil, ck); w.Code != 401 {
		t.Fatal("logout did not revoke")
	}
}
func TestPasswordChangeAndLimits(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	w := request(a, "POST", "/api/password", map[string]string{"currentPassword": "test-password-12345", "newPassword": "updated-password-12345"}, ck)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if request(a, "GET", "/api/state", nil, ck).Code != 401 {
		t.Fatal("old session remains")
	}
	for i := 0; i < 6; i++ {
		request(a, "POST", "/api/login", map[string]string{"password": "bad"}, nil)
	}
	if request(a, "POST", "/api/login", map[string]string{"password": "bad"}, nil).Code != 429 {
		t.Fatal("rate limiter failed")
	}
}
func TestStaticAssetsAndBodyLimits(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	for _, path := range []string{"/", "/app.js", "/style.css", "/vendor/xterm.js", "/vendor/xterm.css"} {
		w := request(a, "GET", path, nil, nil)
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatal("missing asset", path)
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("missing CSP")
		}
	}
	for _, body := range []string{"{} {}", `{"notAField":1}`, `{"schema":1,"dns":{"secret":"` + strings.Repeat("a", 2<<20) + `"}}`} {
		r := httptest.NewRequest("PUT", "http://localhost/api/config", strings.NewReader(body))
		r.Header.Set("X-LinkNest-Request", "1")
		r.AddCookie(ck)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("unbounded/invalid input accepted", w.Code)
		}
	}
}
