package main

import (
	"net/http"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestDecodeDoHRequestMessageGET(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://dns.google/dns-query?dns=AAABAAABAAAAAAAAA2lwdwJjbgAAAQAB", nil)
	if err != nil {
		t.Fatalf("build request failed: %v", err)
	}
	payload, isDoH, err := decodeDoHRequestMessage(req)
	if err != nil {
		t.Fatalf("decode doh get failed: %v", err)
	}
	if !isDoH {
		t.Fatalf("expected doh request")
	}
	if len(payload) == 0 {
		t.Fatalf("expected non-empty payload")
	}
}

func TestDecodeDoHRequestMessagePOST(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://dns.google/dns-query", strings.NewReader("abcdef"))
	if err != nil {
		t.Fatalf("build request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	payload, isDoH, err := decodeDoHRequestMessage(req)
	if err != nil {
		t.Fatalf("decode doh post failed: %v", err)
	}
	if !isDoH {
		t.Fatalf("expected doh request")
	}
	if string(payload) != "abcdef" {
		t.Fatalf("unexpected payload: %q", string(payload))
	}
}

func TestDecodeDoHRequestMessageNonDoH(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/index.html", nil)
	if err != nil {
		t.Fatalf("build request failed: %v", err)
	}
	payload, isDoH, err := decodeDoHRequestMessage(req)
	if err != nil {
		t.Fatalf("decode non-doh failed: %v", err)
	}
	if isDoH {
		t.Fatalf("expected non-doh request")
	}
	if len(payload) != 0 {
		t.Fatalf("expected empty payload")
	}
}

func TestMatchDoHHijackTarget(t *testing.T) {
	dst := M.ParseSocksaddr("1.1.1.1:443")
	if !matchDoHHijackTarget(dst, []string{"cloudflare-dns.com"}, []string{"cloudflare-dns.com"}) {
		t.Fatalf("expected doh hijack target matched")
	}
	if matchDoHHijackTarget(dst, []string{"example.com"}, []string{"cloudflare-dns.com"}) {
		t.Fatalf("expected doh hijack target not matched")
	}
}

func TestMatchDoTHijackTarget(t *testing.T) {
	dst := M.ParseSocksaddr("1.1.1.1:853")
	if !matchDoTHijackTarget(dst, nil, nil) {
		t.Fatalf("empty dot host list should match all")
	}
	if !matchDoTHijackTarget(dst, []string{"dns.google"}, []string{"*.google"}) {
		t.Fatalf("expected dot hijack target matched")
	}
	if matchDoTHijackTarget(dst, []string{"example.com"}, []string{"dns.google"}) {
		t.Fatalf("expected dot hijack target not matched")
	}
}

func TestCanonicalMITMCertHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"  Google.COM.  ", "google.com"},
		{"google.com:443", "google.com"},
		{"[2400:c620:12:8d::a]:443", "2400:c620:12:8d::a"},
		{"2400:c620:12:8d::a", "2400:c620:12:8d::a"},
	}
	for _, tc := range cases {
		got := canonicalMITMCertHost(tc.in)
		if got != tc.want {
			t.Fatalf("canonicalMITMCertHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSelectMITMCertHostForConnect(t *testing.T) {
	if got := selectMITMCertHostForConnect("google.com:443", "google.com"); got != "google.com" {
		t.Fatalf("same host choose failed, got=%q", got)
	}
	if got := selectMITMCertHostForConnect("google.com:443", "facebook.com"); got != "facebook.com" {
		t.Fatalf("mismatch should prefer sni host, got=%q", got)
	}
	if got := selectMITMCertHostForConnect("23.141.52.18:20086", "facebook.com"); got != "facebook.com" {
		t.Fatalf("ip vs domain should prefer sni host, got=%q", got)
	}
	if got := selectMITMCertHostForConnect("google.com:443", ""); got != "google.com" {
		t.Fatalf("empty sni should fallback to connect host, got=%q", got)
	}
}

func TestSelectMITMCertHostForTransparent(t *testing.T) {
	if got := selectMITMCertHostForTransparent("instagram.com", "google.com"); got != "google.com" {
		t.Fatalf("transparent mode should prefer sni host, got=%q", got)
	}
	if got := selectMITMCertHostForTransparent("1.2.3.4:443", "google.com"); got != "google.com" {
		t.Fatalf("transparent ip target should still prefer sni host, got=%q", got)
	}
	if got := selectMITMCertHostForTransparent("google.com:443", ""); got != "google.com" {
		t.Fatalf("transparent mode should fallback to target host, got=%q", got)
	}
}

func TestShouldBlockQUIC(t *testing.T) {
	m := &mitmRuntime{
		hostPatterns: []string{
			"video-dsp.pddpic.com",
			"*.pinduoduo.com",
		},
	}
	if !m.ShouldBlockQUIC(M.ParseSocksaddr("1.1.1.1:443"), []string{"video-dsp.pddpic.com"}) {
		t.Fatalf("expected quic blocked for exact host match")
	}
	if !m.ShouldBlockQUIC(M.ParseSocksaddr("1.1.1.1:443"), []string{"t-dsp.pinduoduo.com"}) {
		t.Fatalf("expected quic blocked for wildcard host match")
	}
	if m.ShouldBlockQUIC(M.ParseSocksaddr("1.1.1.1:80"), []string{"video-dsp.pddpic.com"}) {
		t.Fatalf("expected non-443 not blocked")
	}
	if m.ShouldBlockQUIC(M.ParseSocksaddr("1.1.1.1:443"), []string{"example.com"}) {
		t.Fatalf("expected unrelated host not blocked")
	}
}

func TestRecordURLRejectHit(t *testing.T) {
	m := &mitmRuntime{}
	rule := `^https:\/\/video-dsp\.pddpic\.com\/market-dsp-video\/`
	m.recordURLRejectHit("https://video-dsp.pddpic.com/market-dsp-video/abc", rule)
	m.recordURLRejectHit("https://video-dsp.pddpic.com/market-dsp-video/def", rule)
	count, at, lastURL, lastRule, top := m.URLRejectStats()
	if count != 2 {
		t.Fatalf("expected hit count 2, got %d", count)
	}
	if at.IsZero() {
		t.Fatalf("expected last hit time recorded")
	}
	if lastURL == "" {
		t.Fatalf("expected last hit url recorded")
	}
	if lastRule != rule {
		t.Fatalf("expected last hit rule %q, got %q", rule, lastRule)
	}
	if len(top) == 0 || top[0].Rule != rule || top[0].Hits != 2 {
		t.Fatalf("expected top rule hit stats updated, got %+v", top)
	}
	if top[0].LastAt.IsZero() {
		t.Fatalf("expected top rule last hit time recorded")
	}
}
