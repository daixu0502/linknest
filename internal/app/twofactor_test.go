package app

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, v := range []struct {
		seconds int64
		code    string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := totpCode(secret, v.seconds/30); got != v.code {
			t.Fatalf("%d: %s != %s", v.seconds, got, v.code)
		}
	}
	now := time.Unix(1234567890, 0)
	step := now.Unix() / 30
	for _, delta := range []int64{-1, 0, 1} {
		if got, ok := totpStep(secret, totpCode(secret, step+delta), now, -1); !ok || got != step+delta {
			t.Fatal("clock skew", delta)
		}
	}
	for _, code := range []string{"", "12345", "1234567", "１２３４５６", "abcdef", totpCode(secret, step-2)} {
		if _, ok := totpStep(secret, code, now, -1); ok {
			t.Fatal("accepted invalid code", code)
		}
	}
	if _, ok := totpStep(secret, totpCode(secret, step), now, step); ok {
		t.Fatal("replay accepted")
	}
}

func enableTwoFactor(t *testing.T, a *App, ck *http.Cookie) (string, []string) {
	t.Helper()
	w := request(a, "POST", "/api/2fa/begin", map[string]string{"password": "test-password-12345"}, ck)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var begin struct {
		Secret    string
		QRDataURL string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	if len(begin.Secret) != 32 || !strings.HasPrefix(begin.QRDataURL, "data:image/png;base64,") {
		t.Fatal("missing local QR or secret")
	}
	w = request(a, "POST", "/api/2fa/enable", map[string]string{"password": "test-password-12345", "code": totpCode(begin.Secret, time.Now().Unix()/30)}, ck)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result struct{ RecoveryCodes []string }
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.RecoveryCodes) != 10 {
		t.Fatal("missing recovery codes")
	}
	return begin.Secret, result.RecoveryCodes
}

func TestTwoFactorEnrollmentLoginAndRecovery(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	other := request(a, "POST", "/api/login", map[string]string{"username": "admin", "password": "test-password-12345"}, nil).Result().Cookies()[0]
	secret, codes := enableTwoFactor(t, a, ck)
	if request(a, "GET", "/api/state", nil, other).Code != 401 {
		t.Fatal("old session not revoked")
	}
	if request(a, "GET", "/api/state", nil, ck).Code != 200 {
		t.Fatal("verified current session lost")
	}
	disk, err := os.ReadFile(filepath.Join(a.store.dir, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disk), secret) || strings.Contains(string(disk), codes[0]) || !strings.Contains(string(disk), "enc:") {
		t.Fatal("plaintext secret or recovery code persisted")
	}
	for _, path := range []string{"/api/state", "/api/export", "/api/health"} {
		w := request(a, "GET", path, nil, ck)
		if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), codes[0]) || strings.Contains(w.Body.String(), a.auth.TwoFactor.Secret) || strings.Contains(w.Body.String(), a.auth.TwoFactor.RecoveryHashes[0]) {
			t.Fatal("secret leaked", path)
		}
	}
	credentials := map[string]string{"username": "admin", "password": "test-password-12345"}
	w := request(a, "POST", "/api/login", credentials, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"twoFactorRequired":true`) || len(w.Result().Cookies()) != 0 {
		t.Fatal("password alone issued session", w.Body.String())
	}
	credentials["code"] = totpCode(secret, time.Now().Unix()/30+1)
	w = request(a, "POST", "/api/login", credentials, nil)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("TOTP login failed", w.Body.String())
	}
	if request(a, "POST", "/api/login", credentials, nil).Code != 401 {
		t.Fatal("TOTP replay accepted")
	}
	credentials["code"] = strings.ToLower(codes[0])
	w = request(a, "POST", "/api/login", credentials, nil)
	if w.Code != 200 || len(a.auth.TwoFactor.RecoveryHashes) != 9 {
		t.Fatal("recovery login failed", w.Body.String())
	}
	if request(a, "POST", "/api/login", credentials, nil).Code != 401 {
		t.Fatal("recovery replay accepted")
	}
	// Restart must retain 2FA and consumed-code state.
	restarted, err := newApp(a.store.dir, a.admin, false)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.engine.close()
	defer restarted.dns.close()
	defer restarted.certs.close()
	if request(restarted, "POST", "/api/login", credentials, nil).Code != 401 {
		t.Fatal("consumed code returned after restart")
	}
	credentials["code"] = codes[1]
	if w = request(restarted, "POST", "/api/login", credentials, nil); w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("restart lost 2FA", w.Body.String())
	}
}

func TestTwoFactorAccountChangeRotationAndDisable(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	_, codes := enableTwoFactor(t, a, ck)
	w := request(a, "POST", "/api/account", map[string]string{"username": "new-admin", "currentPassword": "test-password-12345", "newPassword": "new-test-password-12345"}, ck)
	if w.Code != 403 {
		t.Fatal("account changed without second factor")
	}
	w = request(a, "POST", "/api/account", map[string]string{"username": "new-admin", "currentPassword": "test-password-12345", "newPassword": "new-test-password-12345", "code": codes[0]}, ck)
	if w.Code != 200 || a.auth.TwoFactor == nil {
		t.Fatal("account change dropped 2FA", w.Body.String())
	}
	credentials := map[string]string{"username": "new-admin", "password": "new-test-password-12345"}
	w = request(a, "POST", "/api/login", credentials, nil)
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("account change bypassed 2FA")
	}
	credentials["code"] = codes[1]
	w = request(a, "POST", "/api/login", credentials, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	ck = w.Result().Cookies()[0]
	w = request(a, "POST", "/api/2fa/recovery", map[string]string{"password": "new-test-password-12345", "code": codes[2]}, ck)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result struct{ RecoveryCodes []string }
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.RecoveryCodes) != 10 {
		t.Fatal("rotation missing codes")
	}
	credentials["code"] = codes[3]
	if request(a, "POST", "/api/login", credentials, nil).Code != 401 {
		t.Fatal("old recovery code remained")
	}
	w = request(a, "POST", "/api/2fa/disable", map[string]string{"password": "new-test-password-12345", "code": result.RecoveryCodes[0]}, ck)
	if w.Code != 200 || a.auth.TwoFactor != nil {
		t.Fatal("disable failed", w.Body.String())
	}
	delete(credentials, "code")
	w = request(a, "POST", "/api/login", credentials, nil)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("disabled 2FA still required")
	}
}

func TestTwoFactorEnrollmentBoundariesAndLimits(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	if request(a, "POST", "/api/2fa/begin", map[string]string{"password": "test-password-12345"}, nil).Code != 401 {
		t.Fatal("unauthenticated enrollment")
	}
	if request(a, "GET", "/api/2fa/begin", nil, ck).Code != 405 {
		t.Fatal("method accepted")
	}
	w := request(a, "POST", "/api/2fa/begin", map[string]string{"password": "test-password-12345"}, ck)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	pending := a.twoFactorPending
	other := request(a, "POST", "/api/login", map[string]string{"username": "admin", "password": "test-password-12345"}, nil).Result().Cookies()[0]
	proof := map[string]string{"password": "test-password-12345", "code": totpCode(pending.secret, time.Now().Unix()/30)}
	if request(a, "POST", "/api/2fa/enable", proof, other).Code != 409 {
		t.Fatal("other session confirmed enrollment")
	}
	pending.expires = time.Now().Add(-time.Second)
	if request(a, "POST", "/api/2fa/enable", proof, ck).Code != 409 {
		t.Fatal("expired enrollment accepted")
	}
	pending.expires = time.Now().Add(time.Minute)
	proof["code"] = "abcdef"
	for i := 0; i < 6; i++ {
		if w = request(a, "POST", "/api/2fa/enable", proof, ck); w.Code != 403 {
			t.Fatal("wrong code not rejected", i, w.Body.String())
		}
	}
	proof["code"] = totpCode(pending.secret, time.Now().Unix()/30)
	if request(a, "POST", "/api/2fa/enable", proof, ck).Code != 429 {
		t.Fatal("enrollment rate limit bypassed")
	}
	if a.auth.TwoFactor != nil {
		t.Fatal("failed binding enabled 2FA")
	}
}

func TestTwoFactorMissingKeyAndConcurrentRecovery(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	_, codes := enableTwoFactor(t, a, ck)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- request(a, "POST", "/api/login", map[string]string{"username": "admin", "password": "test-password-12345", "code": codes[0]}, nil).Code
		}()
	}
	wg.Wait()
	close(statuses)
	success := 0
	for code := range statuses {
		if code == 200 {
			success++
		}
	}
	if success != 1 {
		t.Fatal("concurrent recovery use", success)
	}
	keyPath := filepath.Join(a.store.dir, "master.key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := newStore(a.store.dir); err == nil {
		t.Fatal("missing key silently replaced")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("generated new key over encrypted auth")
	}
}

func TestTwoFactorLoginLimitAndFailedSave(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	_, codes := enableTwoFactor(t, a, ck)
	credentials := map[string]string{"username": "admin", "password": "test-password-12345", "code": "abcdef"}
	for i := 0; i < 6; i++ {
		if request(a, "POST", "/api/login", credentials, nil).Code != 401 {
			t.Fatal("invalid OTP accepted")
		}
	}
	credentials["code"] = codes[0]
	if request(a, "POST", "/api/login", credentials, nil).Code != 429 {
		t.Fatal("OTP brute-force limit bypassed")
	}
	if len(a.auth.TwoFactor.RecoveryHashes) != 10 {
		t.Fatal("blocked login consumed recovery code")
	}
	a.mu.Lock()
	a.failures = map[string]attempt{}
	for i := 0; i < 32; i++ {
		a.sessions[string(rune('a'+i))] = session{expires: time.Now().Add(time.Hour)}
	}
	a.mu.Unlock()
	if request(a, "POST", "/api/login", credentials, nil).Code != 429 {
		t.Fatal("session cap bypassed")
	}
	if len(a.auth.TwoFactor.RecoveryHashes) != 10 {
		t.Fatal("full session table consumed recovery code")
	}
	a.mu.Lock()
	a.sessions = map[string]session{}
	a.mu.Unlock()
	// An unavailable auth file must fail closed without consuming a recovery code.
	authPath := filepath.Join(a.store.dir, "auth.json")
	if err := os.Rename(authPath, authPath+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(authPath, 0700); err != nil {
		t.Fatal(err)
	}
	if w := request(a, "POST", "/api/login", credentials, nil); w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatal("save failure issued a session")
	}
	if len(a.auth.TwoFactor.RecoveryHashes) != 10 {
		t.Fatal("save failure consumed recovery code")
	}
	if err := os.Remove(authPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(authPath+".saved", authPath); err != nil {
		t.Fatal(err)
	}
	if w := request(a, "POST", "/api/login", credentials, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}
