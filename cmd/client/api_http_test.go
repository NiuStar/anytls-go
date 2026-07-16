package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsHostnameMismatchErrorText(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		match bool
	}{
		{
			name:  "curl no alternative name",
			text:  "SSL: no alternative certificate subject name matches target hostname 'www.google.com'",
			match: true,
		},
		{
			name:  "x509 valid for other domain",
			text:  "x509: certificate is valid for *.facebook.com, facebook.com, not www.google.com",
			match: true,
		},
		{
			name:  "generic timeout",
			text:  "dial tcp: i/o timeout",
			match: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := isHostnameMismatchErrorText(tc.text)
			if got != tc.match {
				t.Fatalf("unexpected result for %q: got=%v want=%v", tc.text, got, tc.match)
			}
		})
	}
}

func TestDNSProbeServerWeight(t *testing.T) {
	if got, want := dnsProbeServerWeight("1.1.1.1:53"), 5; got != want {
		t.Fatalf("unexpected weight for 1.1.1.1: got=%d want=%d", got, want)
	}
	if got, want := dnsProbeServerWeight("127.0.0.1:53"), 2; got != want {
		t.Fatalf("unexpected weight for 127.0.0.1: got=%d want=%d", got, want)
	}
	if got, want := dnsProbeServerWeight("223.5.5.5:53"), 4; got != want {
		t.Fatalf("unexpected weight for 223.5.5.5: got=%d want=%d", got, want)
	}
}

func TestShouldRetryLatencyProbeErrorIncludesTimeout(t *testing.T) {
	cases := []string{
		"context deadline exceeded",
		"dial tcp: i/o timeout",
		"operation timed out",
	}
	for _, tc := range cases {
		if !shouldRetryLatencyProbeError(tc) {
			t.Fatalf("expected retryable latency probe error: %q", tc)
		}
	}
}

func TestClassifyHTTPSProbeErrorKind(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "reset", err: errors.New("read: connection reset by peer"), want: "upstream_reset"},
		{name: "timeout", err: errors.New("context deadline exceeded"), want: "upstream_timeout"},
		{name: "dns", err: errors.New("lookup www.google.com: no such host"), want: "dns_error"},
		{name: "unreachable", err: errors.New("connect: no route to host"), want: "upstream_unreachable"},
		{name: "mismatch", err: errors.New("x509: certificate is valid for *.facebook.com, not www.google.com"), want: "hostname_mismatch"},
	}
	for _, tc := range cases {
		if got := classifyHTTPSProbeErrorKind(tc.err); got != tc.want {
			t.Fatalf("%s: got=%q want=%q", tc.name, got, tc.want)
		}
	}
}

func TestShouldRebuildHTTPSProbeClient(t *testing.T) {
	if !shouldRebuildHTTPSProbeClient(errors.New("read: connection reset by peer")) {
		t.Fatalf("expected rebuild on reset")
	}
	if shouldRebuildHTTPSProbeClient(errors.New("context deadline exceeded")) {
		t.Fatalf("timeout should not force rebuild")
	}
}

func TestHTTPSProbeRetryBackoff(t *testing.T) {
	if got := httpsProbeRetryBackoff(1); got != 120*time.Millisecond {
		t.Fatalf("attempt1 backoff=%s", got)
	}
	if got := httpsProbeRetryBackoff(2); got != 260*time.Millisecond {
		t.Fatalf("attempt2 backoff=%s", got)
	}
	if got := httpsProbeRetryBackoff(3); got != 420*time.Millisecond {
		t.Fatalf("attempt3 backoff=%s", got)
	}
}

func TestAuthClientKeyIgnoresUntrustedForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/current", nil)
	req.RemoteAddr = "192.0.2.10:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.25")
	if got := authClientKey(req); got != "192.0.2.10" {
		t.Fatalf("auth client key=%q want real peer address", got)
	}
}

func TestAPIRequestGuardRejectsCrossSiteMutation(t *testing.T) {
	nextCalled := false
	handler := apiRequestGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18990/api/v1/shutdown", nil)
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", resp.Code, http.StatusForbidden)
	}
	if nextCalled {
		t.Fatalf("cross-site mutation reached protected handler")
	}
}

func TestAPIRequestGuardAllowsCLIWithoutOrigin(t *testing.T) {
	nextCalled := false
	handler := apiRequestGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18990/api/v1/switch", strings.NewReader(`{"name":"node-1"}`))
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent || !nextCalled {
		t.Fatalf("origin-less CLI request rejected: status=%d called=%v", resp.Code, nextCalled)
	}
}

func TestDecodeJSONBodyRejectsOversizedRequest(t *testing.T) {
	payload := `{"value":"` + strings.Repeat("x", apiMaxRequestBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1/api/v1/config", strings.NewReader(payload))
	var out map[string]any
	if err := decodeJSONBody(req, &out); err == nil {
		t.Fatalf("expected oversized request body to be rejected")
	}
}
