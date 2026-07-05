package util

import (
	"os"
	"strings"
)

const (
	defaultWireUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.7632.110 Safari/537.36"
	defaultWireClientTag = ""
	defaultMITMCACN      = "Local Root CA"
	defaultMITMCAOrg     = "Local Trust Services"
)

func sanitizeWireToken(raw string, fallback string, maxLen int) string {
	token := strings.TrimSpace(raw)
	if token == "" {
		token = fallback
	}
	token = strings.ReplaceAll(token, "\r", " ")
	token = strings.ReplaceAll(token, "\n", " ")
	token = strings.ReplaceAll(token, "\t", " ")
	token = strings.TrimSpace(token)
	if token == "" {
		token = fallback
	}
	if maxLen > 0 && len(token) > maxLen {
		token = token[:maxLen]
	}
	return token
}

// WireUserAgent returns the HTTP User-Agent used by outbound runtime probes/fetches.
// Override via ANYTLS_WIRE_USER_AGENT when needed.
func WireUserAgent() string {
	return sanitizeWireToken(os.Getenv("ANYTLS_WIRE_USER_AGENT"), defaultWireUserAgent, 256)
}

// WireClientTag returns the optional value carried in session cmdSettings "client" field.
// Empty by default; override via ANYTLS_WIRE_CLIENT_TAG when needed for diagnostics.
func WireClientTag() string {
	return sanitizeWireToken(os.Getenv("ANYTLS_WIRE_CLIENT_TAG"), defaultWireClientTag, 96)
}

// WireMITMCACN returns the CN used when generating MITM root CA certificate.
// Override via ANYTLS_WIRE_MITM_CA_CN.
func WireMITMCACN() string {
	return sanitizeWireToken(os.Getenv("ANYTLS_WIRE_MITM_CA_CN"), defaultMITMCACN, 96)
}

// WireMITMCAOrg returns the organization used when generating MITM root CA certificate.
// Override via ANYTLS_WIRE_MITM_CA_ORG.
func WireMITMCAOrg() string {
	return sanitizeWireToken(os.Getenv("ANYTLS_WIRE_MITM_CA_ORG"), defaultMITMCAOrg, 96)
}
