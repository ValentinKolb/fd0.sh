package httpguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReadBodyEnforcesExactLimit(t *testing.T) {
	body, err := ReadBody(strings.NewReader("1234"), 4)
	if err != nil {
		t.Fatalf("exact-size body rejected: %v", err)
	}
	if string(body) != "1234" {
		t.Fatalf("body = %q, want 1234", body)
	}

	_, err = ReadBody(strings.NewReader("12345"), 4)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized body error = %v, want ErrResponseTooLarge", err)
	}
}

func TestRejectRedirectDoesNotReachPrivateDestination(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationRequests.Add(1)
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := &http.Client{CheckRedirect: RejectRedirect}
	resp, err := client.Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}
	if got := destinationRequests.Load(); got != 0 {
		t.Fatalf("private redirect destination received %d requests", got)
	}
}
