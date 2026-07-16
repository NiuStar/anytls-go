package main

import "testing"

func TestLooksLikeHTTPRequest(t *testing.T) {
	for _, raw := range []string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HEAD /health HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"POST /submit HTTP/1.1\r\nHost: example.com\r\n\r\n",
	} {
		if !looksLikeHTTPRequest([]byte(raw)) {
			t.Fatalf("expected HTTP request detection for %q", raw)
		}
	}
}

func TestLooksLikeHTTPRequestRejectsBinaryAuthentication(t *testing.T) {
	raw := make([]byte, 64)
	copy(raw, []byte("GET-not-an-http-request"))
	if looksLikeHTTPRequest(raw) {
		t.Fatalf("binary authentication payload must not be classified as HTTP")
	}
}
