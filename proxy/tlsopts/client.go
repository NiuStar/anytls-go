package tlsopts

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
)

type ClientOptions struct {
	Server        string
	SNI           string
	AllowInsecure bool
	CACertPath    string
	CertSHA256    string
}

func BuildClientConfig(opts ClientOptions) (*tls.Config, error) {
	server := strings.TrimSpace(opts.Server)
	if server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", server, err)
	}

	certPin := strings.TrimSpace(opts.CertSHA256)
	if certPin != "" {
		cfg := newClientTLSConfig(false)
		serverName := strings.TrimSpace(opts.SNI)
		if serverName == "" {
			host, _, splitErr := net.SplitHostPort(server)
			if splitErr != nil {
				return nil, fmt.Errorf("derive tls server name failed: %w", splitErr)
			}
			serverName = strings.TrimSpace(host)
		}
		cfg.ServerName = serverName
		if err := applyCertificatePin(cfg, certPin); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	cfg := newClientTLSConfig(opts.AllowInsecure)
	if opts.AllowInsecure {
		cfg.ServerName = strings.TrimSpace(opts.SNI)
		if cfg.ServerName == "" {
			// Disable SNI when verification is skipped.
			cfg.ServerName = "127.0.0.1"
		}
		return cfg, nil
	}

	serverName := strings.TrimSpace(opts.SNI)
	if serverName == "" {
		host, _, splitErr := net.SplitHostPort(server)
		if splitErr != nil {
			return nil, fmt.Errorf("derive tls server name failed: %w", splitErr)
		}
		serverName = strings.TrimSpace(host)
	}
	if serverName == "" {
		return nil, fmt.Errorf("tls verify enabled but server name is empty")
	}
	cfg.ServerName = serverName

	caPath := strings.TrimSpace(opts.CACertPath)
	if caPath == "" {
		return cfg, nil
	}
	pool, err := LoadRootCAsFromFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("load ca cert failed (%s): %w", caPath, err)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

func LoadRootCAsFromFile(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("invalid PEM certificates")
	}
	return pool, nil
}
