package tlsopts

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

const certSHA256HexLen = sha256.Size * 2

func NormalizeCertSHA256(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.TrimPrefix(normalized, "sha256:")
	normalized = strings.TrimPrefix(normalized, "sha256=")
	normalized = strings.NewReplacer(":", "", " ", "", "-", "").Replace(normalized)
	if normalized == "" {
		return "", nil
	}
	if len(normalized) != certSHA256HexLen {
		return "", fmt.Errorf("cert_sha256 must be %d hex characters", certSHA256HexLen)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("cert_sha256 must be hex: %w", err)
	}
	return normalized, nil
}

func CertificateSHA256FromDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func CertificateSHA256FromPEMFile(path string) (string, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block != nil && block.Type == "CERTIFICATE" {
		return CertificateSHA256FromDER(block.Bytes), nil
	}
	return CertificateSHA256FromDER(raw), nil
}

func applyCertificatePin(cfg *tls.Config, rawPin string) error {
	pin, err := NormalizeCertSHA256(rawPin)
	if err != nil || pin == "" {
		return err
	}
	cfg.InsecureSkipVerify = true
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("server did not provide certificate")
		}
		got := CertificateSHA256FromDER(rawCerts[0])
		if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
			return fmt.Errorf("server certificate sha256 mismatch: got %s", got)
		}
		return nil
	}
	return nil
}
