package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "ptrmaker.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPtrNameToIPv4(t *testing.T) {
	got := ptrNameToIP("4.3.2.1.in-addr.arpa.")
	if got != "1.2.3.4" {
		t.Fatalf("got %q, want 1.2.3.4", got)
	}
}

func TestPtrNameToIPv6(t *testing.T) {
	got := ptrNameToIP("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")
	if got != "::1" {
		t.Fatalf("got %q, want ::1", got)
	}
}

func TestBestNamePrefersOriginalQuery(t *testing.T) {
	s := testStore(t)
	if err := s.LearnName("203.0.113.10", "thing.amazonaws.com", "answer", 300); err != nil {
		t.Fatal(err)
	}
	if err := s.LearnName("203.0.113.10", "app.example.com", "query", 300); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.BestName("203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got != "app.example.com" {
		t.Fatalf("got %q ok=%v, want app.example.com", got, ok)
	}
}

func TestTrustAnchorNameIgnored(t *testing.T) {
	s := testStore(t)
	if err := s.LearnName("192.0.2.1", "_ta-4f66-9728", "query", 300); err != nil {
		t.Fatal(err)
	}
	rows, err := s.LookupIP("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("trust-anchor signal was learned: %#v", rows)
	}
}

func TestLookupAPI(t *testing.T) {
	s := testStore(t)
	if err := s.LearnName("203.0.113.20", "api.example.com", "query", 300); err != nil {
		t.Fatal(err)
	}
	w := NewWebServer("127.0.0.1:0", s, NewMetrics())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/lookup/203.0.113.20", nil)
	rec := httptest.NewRecorder()
	w.server.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "api.example.com") {
		t.Fatalf("lookup response missing learned name: %s", rec.Body.String())
	}
}
