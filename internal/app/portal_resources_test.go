package app

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPortalCanvasResources(t *testing.T) {
	p := newPortal(testStore(t), quiet)
	route := WebRoute{ID: "panel", Backend: "bookmarks", PublicAccess: true}
	for _, item := range []struct{ path, mime string }{
		{"scrollbars.css", "text/css"}, {"button-feedback.css", "text/css"}, {"grain.svg", "image/svg+xml"},
	} {
		w := httptest.NewRecorder()
		p.serve(route, w, httptest.NewRequest("GET", "http://panel.example/__linknest/"+item.path+"?v="+version, nil))
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), item.mime) || w.Body.Len() == 0 {
			t.Fatal(item.path, w.Code, w.Header())
		}
	}
	w := httptest.NewRecorder()
	p.serve(route, w, httptest.NewRequest("GET", "http://panel.example/", nil))
	for _, required := range []string{"canvas-background", "/__linknest/scrollbars.css?v=" + version, "/__linknest/button-feedback.css?v=" + version, "public-portal", "viewport-fit=cover"} {
		if !strings.Contains(w.Body.String(), required) {
			t.Fatal("missing", required)
		}
	}
	if strings.Contains(w.Body.String(), "theme-color") {
		t.Fatal("fixed theme-color overrides Safari's canvas sampling")
	}
	a := testApp(t)
	if r := request(a, "GET", "/scrollbars.css?v="+version, nil, nil); r.Code != 200 {
		t.Fatal("admin scrollbar resource unavailable", r.Code)
	}
	if r := request(a, "GET", "/button-feedback.css?v="+version, nil, nil); r.Code != 200 {
		t.Fatal("admin button feedback resource unavailable", r.Code)
	}
}
