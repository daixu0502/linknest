package app

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPanelClockStyleValidationAndPersistence(t *testing.T) {
	s, e := newStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, style := range []string{"", "vector", "simple", "digital", "stacked"} {
		c := s.snapshot()
		c.Panel.ClockStyle = style
		c.Panel.ShowClock = true
		if e := validate(c, "127.0.0.1:17880"); e != nil {
			t.Fatal(style, e)
		}
		if e := s.save(c); e != nil {
			t.Fatal(e)
		}
		reloaded, e := newStore(s.dir)
		if e != nil || reloaded.snapshot().Panel.ClockStyle != style {
			t.Fatal("clock style did not persist", style, e)
		}
		p := newPortal(s, func(string, string) {})
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "http://panel.example.com/", nil)
		p.serve(WebRoute{ID: "panel", Name: "panel", Backend: "bookmarks", PublicAccess: true}, w, r)
		expected := style
		if expected == "" {
			expected = "vector"
		}
		if w.Code != 200 || !strings.Contains(w.Body.String(), `data-clock-style="`+expected+`"`) {
			t.Fatal("clock style not rendered", style, w.Code)
		}
	}
	c := s.snapshot()
	c.Panel.ClockStyle = "unknown"
	if validate(c, "127.0.0.1:17880") == nil {
		t.Fatal("invalid style accepted")
	}
}
