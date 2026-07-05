package util

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerateKeyPairUsesTenYearValidity(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	cert, err := GenerateKeyPair(func() time.Time { return now }, "example.com")
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatalf("generated certificate is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate failed: %v", err)
	}
	wantNotBefore := now.Add(-1 * time.Hour)
	wantNotAfter := now.AddDate(10, 0, 0)
	if !leaf.NotBefore.Equal(wantNotBefore) {
		t.Fatalf("unexpected NotBefore: got %s want %s", leaf.NotBefore, wantNotBefore)
	}
	if !leaf.NotAfter.Equal(wantNotAfter) {
		t.Fatalf("unexpected NotAfter: got %s want %s", leaf.NotAfter, wantNotAfter)
	}
}
