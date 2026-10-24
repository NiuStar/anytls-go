package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func subscriptionFixture(t *testing.T) (*tls.Config, subscriptionConfig) {
	t.Helper()
	cfg, _, err := buildServerTLSConfig("127.0.0.1:8443", "", "", "", "", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return cfg, subscriptionConfig{PublicIP: "8.8.8.8", Listen: "127.0.0.1:443", Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), NodeName: "fixture"}
}
func TestSubscriptionActiveCertificateAndRoute(t *testing.T) {
	cfg, sub := subscriptionFixture(t)
	h, body, leaf, err := subscriptionHandler(sub, cfg, "0.0.0.0:8443", "secret")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	der := sha256.Sum256(cert.Raw)
	if leaf != der {
		t.Fatal("leaf pin mismatch")
	}
	var doc struct {
		Proxies []map[string]any `json:"proxies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	n := doc.Proxies[0]
	if n["certificate-public-key-sha256"] != base64.StdEncoding.EncodeToString(spki[:]) || n["password"] != "secret" || n["server"] != sub.PublicIP || n["skip-cert-verify"] != false || n["port"] != float64(8443) {
		t.Fatal("wrong native node")
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/subscribe/" + sub.Token, 200}, {"HEAD", "/subscribe/" + sub.Token, 200}, {"POST", "/subscribe/" + sub.Token, 404}, {"GET", "/subscribe/wrong", 404}, {"GET", "/subscribe/" + sub.Token + "?x=1", 404}, {"GET", "/subscribe/%41" + sub.Token[1:], 404}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.method, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cache header")
		}
		if tc.method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD body")
		}
	}
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = cfg.Clone()
	ts.StartTLS()
	defer ts.Close()
	client := ts.Client()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || sha256.Sum256(cs.PeerCertificates[0].Raw) != leaf {
			return errors.New("pin mismatch")
		}
		return nil
	}}
	resp, err := client.Get(ts.URL + "/subscribe/" + sub.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(body) {
		t.Fatal("TLS body mismatch")
	}
}
func TestSubscriptionPrivatePersistenceAndValidation(t *testing.T) {
	_, sub := subscriptionFixture(t)
	path := filepath.Join(t.TempDir(), "subscription.json")
	if err := saveSubscriptionConfig(path, sub); err != nil {
		t.Fatal(err)
	}
	got, err := loadSubscriptionConfig(path)
	if err != nil || got != sub {
		t.Fatal("roundtrip", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("not private")
	}
	os.Chmod(path, 0644)
	if _, err := loadSubscriptionConfig(path); err == nil {
		t.Fatal("accepted public config")
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.1", "203.0.113.1", "240.0.0.1", "100.64.0.1", "2001:db8::1", "::", "2001:2::1", "3fff::1", "8.8.8.8%eth0", "::ffff:8.8.8.8", "192.0.0.8", "192.88.99.1", "example.com"} {
		sub.PublicIP = ip
		if validateSubscriptionConfig(sub) == nil {
			t.Fatalf("accepted %s", ip)
		}
	}
	sub.PublicIP = "2606:4700:4700::1111"
	if err := validateSubscriptionConfig(sub); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(subscriptionURL(sub, [32]byte{}), "https://[2606:4700:4700::1111]/") {
		t.Fatal("IPv6 URL")
	}
	sub.Token = strings.Repeat("!", 43)
	if validateSubscriptionConfig(sub) == nil {
		t.Fatal("invalid token")
	}
}
func TestSubscriptionBindFailureClosesAnyTLSAndCancellation(t *testing.T) {
	cfg, sub := subscriptionFixture(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	sub.Listen = busy.Addr().String()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	if _, _, err := startServerListeners(context.Background(), addr, &sub, cfg, "secret"); err == nil {
		t.Fatal("bind accepted")
	}
	probe, err = net.Listen("tcp", addr)
	if err != nil {
		t.Fatal("leaked AnyTLS listener")
	}
	probe.Close()
	sub.Listen = "127.0.0.1:0" // production config validation forbids zero; listener helper uses OS assignment in tests.
	ctx, cancel := context.WithCancel(context.Background())
	listener, server, err := startServerListeners(ctx, addr, &sub, cfg, "secret")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	server.Close()
	listener.Close()
	probe, err = net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
}
func TestSubscriptionRejectsDynamicCertificate(t *testing.T) {
	cfg, sub := subscriptionFixture(t)
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cfg.Certificates[0], nil }
	if _, _, _, err := subscriptionHandler(sub, cfg, "0.0.0.0:8443", "secret"); err == nil {
		t.Fatal("dynamic cert accepted")
	}
}

func TestSubscriptionCheckActiveRejectsChangedDiskIdentity(t *testing.T) {
	cfg, sub := subscriptionFixture(t)
	h, body, pin, err := subscriptionHandler(sub, cfg, "0.0.0.0:8443", "secret")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); h.ServeHTTP(w, r) }))
	ts.TLS = cfg.Clone()
	ts.StartTLS()
	defer ts.Close()
	sub.Listen = strings.TrimPrefix(ts.URL, "https://")
	if err := checkActiveSubscription(sub, pin, body); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("positive HTTP missing")
	}
	pin[0] ^= 1
	if checkActiveSubscription(sub, pin, body) == nil {
		t.Fatal("wrong identity accepted")
	}
	if requests.Load() != 1 {
		t.Fatal("token sent despite wrong certificate pin")
	}
}
