package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAliDNSMock(t *testing.T) {
	// Local mock only: no real account, no external DNS writes.
	current := "203.0.113.8"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sig := r.Form.Get("Signature")
		r.Form.Del("Signature")
		if sig != aliSignature(r.Form, "fake-secret") {
			t.Error("signature mismatch")
		}
		switch r.Form.Get("Action") {
		case "DescribeDomainRecords":
			fmt.Fprintf(w, `{"TotalCount":1,"DomainRecords":{"Record":[{"RecordId":"mock-id","RR":"home","Type":"A","Value":%q}]}}`, current)
		case "UpdateDomainRecord":
			if r.Form.Get("RecordId") != "mock-id" {
				t.Error("wrong record changed")
			}
			calls++
			current = r.Form.Get("Value")
			w.Write([]byte(`{"RecordId":"mock-id"}`))
		default:
			t.Error("unexpected action", r.Form.Get("Action"))
		}
	}))
	defer srv.Close()
	api := AliDNS{ID: "fake-id", Secret: "fake-secret", Endpoint: srv.URL, Client: srv.Client()}
	changed, e := api.upsert(context.Background(), "example.com", "home", "A", current)
	if e != nil || changed || calls != 0 {
		t.Fatal("unchanged record written", changed, e, calls)
	}
	changed, e = api.upsert(context.Background(), "example.com", "home", "A", "203.0.113.9")
	if e != nil || !changed || calls != 1 {
		t.Fatal(changed, e, calls)
	}
	if encodeAli("a b+~*") != "a%20b%2B~%2A" {
		t.Fatal("AliDNS percent encoding")
	}
}
func TestAliDNSRefusesAmbiguous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("Action") != "DescribeDomainRecords" {
			t.Fatal("wrote ambiguous records")
		}
		w.Write([]byte(`{"TotalCount":2,"DomainRecords":{"Record":[{"RR":"home","Type":"A"},{"RR":"home","Type":"A"}]}}`))
	}))
	defer srv.Close()
	_, e := (AliDNS{ID: "x", Secret: "y", Endpoint: srv.URL}).upsert(context.Background(), "example.com", "home", "A", "203.0.113.1")
	if e == nil {
		t.Fatal("ambiguous records accepted")
	}
}
