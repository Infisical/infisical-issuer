package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func selfSignedClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestNewTLSConfig(t *testing.T) {
	t.Run("nil without a CA or client certificate", func(t *testing.T) {
		cfg, err := NewTLSConfig("", nil)
		require.NoError(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("rejects a CA with no certificates", func(t *testing.T) {
		_, err := NewTLSConfig("not a pem", nil)
		require.Error(t, err)
	})

	t.Run("presents the client certificate and trusts the custom CA", func(t *testing.T) {
		var presented string
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) > 0 {
				presented = r.TLS.PeerCertificates[0].Subject.CommonName
			}
		}))
		srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
		srv.StartTLS()
		defer srv.Close()

		client := selfSignedClientCert(t)
		ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
		cfg, err := NewTLSConfig(ca, &client)
		require.NoError(t, err)

		res, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}).Get(srv.URL)
		require.NoError(t, err)
		_ = res.Body.Close()
		assert.Equal(t, "workload", presented)
	})
}
