package tlsopts

import "crypto/tls"

var hardenedTLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

var hardenedCurvePreferences = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

func applyCommonTLSHardening(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg.MinVersion = tls.VersionTLS12
	cfg.CipherSuites = append([]uint16(nil), hardenedTLS12CipherSuites...)
	cfg.CurvePreferences = append([]tls.CurveID(nil), hardenedCurvePreferences...)
	return cfg
}

func newClientTLSConfig(allowInsecure bool) *tls.Config {
	return applyCommonTLSHardening(&tls.Config{
		InsecureSkipVerify: allowInsecure,
	})
}

func newServerTLSConfig() *tls.Config {
	cfg := applyCommonTLSHardening(&tls.Config{})
	// Disable stateful ticket material by default to reduce long-lived resumption
	// secrets and cross-connection linkability. Operators that need resumption can
	// add an explicit configurable opt-in later.
	cfg.SessionTicketsDisabled = true
	return cfg
}
