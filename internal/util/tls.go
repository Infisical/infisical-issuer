package util

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// NewTLSConfig returns nil when neither a custom CA nor a client certificate is set,
// leaving the transport's defaults in place. A custom CA is appended to the system roots.
func NewTLSConfig(caCertificate string, clientCertificate *tls.Certificate) (*tls.Config, error) {
	if caCertificate == "" && clientCertificate == nil {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caCertificate != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caCertificate)) {
			return nil, fmt.Errorf("no valid certificates found in tls.caCertificate")
		}
		cfg.RootCAs = pool
	}
	if clientCertificate != nil {
		cfg.Certificates = []tls.Certificate{*clientCertificate}
	}
	return cfg, nil
}
