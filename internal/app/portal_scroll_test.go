package app

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPortalScrollBranches(t *testing.T) {
	p := newPortal(testStore(t), quiet)
	p.sessions["test"] = portalSession{Route: "protected", Hash: "hashed", Expires: time.Now().Add(time.Hour)}
	for _, tc := range []struct {
		name, backend         string
		public, authenticated bool
	}{
		{"public-panel", "bookmarks", true, false},
		{"protected-panel", "bookmarks", false, true},
		{"panel-login", "bookmarks", false, false},
		{"public-wol", "wol", true, false},
		{"protected-wol", "wol", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := WebRoute{ID: "protected", Backend: tc.backend, PublicAccess: tc.public, AccessPassword: "hashed"}
			r := httptest.NewRequest("GET", "http://panel.example/", nil)
			if tc.authenticated {
				r.Header.Set("Cookie", "ln_portal_protected=test")
			}
			w := httptest.NewRecorder()
			p.serve(route, w, r)
			body := w.Body.String()
			if w.Code != 200 {
				t.Fatal(w.Code, body)
			}
			panel := tc.backend == "bookmarks" && (tc.public || tc.authenticated)
			for _, marker := range []string{`class="panel-page"`, `class="panel-controls"`, `class="cards-area"`} {
				if strings.Contains(body, marker) != panel {
					t.Fatal("incorrect scroll branch", marker)
				}
			}
			wantLogout := tc.authenticated && !tc.public
			if (strings.Count(body, `class="portal-auth logout-form"`) == 1) != wantLogout {
				t.Fatal("incorrect logout branch")
			}
		})
	}
}
