package signer

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
)

func TestIsTerminal(t *testing.T) {
	assert.True(t, IsTerminal(&terminalError{msg: "rejected"}))
	assert.True(t, IsTerminal(fmt.Errorf("wrapped: %w", &terminalError{msg: "policy"})))
	assert.False(t, IsTerminal(errors.New("transient network error")))
	assert.False(t, IsTerminal(nil))
}

// certPEM returns a syntactically valid PEM CERTIFICATE block. The body does not
// need to be a real DER certificate for the chain-splitting logic, which only
// decodes PEM block boundaries.
func certPEM(body string) string {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte(body)}
	return string(pem.EncodeToMemory(block))
}

func countCertBlocks(t *testing.T, b []byte) int {
	t.Helper()
	count := 0
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		assert.Equal(t, "CERTIFICATE", block.Type)
		count++
	}
	return count
}

func TestAssemble(t *testing.T) {
	leaf := certPEM("leaf")
	intermediate := certPEM("intermediate")
	root := certPEM("root")

	t.Run("leaf with intermediate and root chain", func(t *testing.T) {
		res, err := assemble(leaf, intermediate+root)
		require.NoError(t, err)
		// Certificate is the leaf followed by the intermediates (not the root).
		assert.Equal(t, 2, countCertBlocks(t, res.Certificate))
		// CA is the root on its own.
		assert.Equal(t, 1, countCertBlocks(t, res.CA))
	})

	t.Run("leaf with root-only chain", func(t *testing.T) {
		res, err := assemble(leaf, root)
		require.NoError(t, err)
		assert.Equal(t, 1, countCertBlocks(t, res.Certificate))
		assert.Equal(t, 1, countCertBlocks(t, res.CA))
	})

	t.Run("no chain", func(t *testing.T) {
		res, err := assemble(leaf, "")
		require.NoError(t, err)
		assert.Equal(t, 1, countCertBlocks(t, res.Certificate))
		assert.Nil(t, res.CA)
	})
}

func TestSplitRootCACertificate(t *testing.T) {
	intermediate1 := certPEM("intermediate-1")
	intermediate2 := certPEM("intermediate-2")
	root := certPEM("root")

	intermediates, gotRoot, err := splitRootCACertificate([]byte(intermediate1 + intermediate2 + root))
	require.NoError(t, err)
	assert.Equal(t, 2, countCertBlocks(t, intermediates))
	assert.Equal(t, 1, countCertBlocks(t, gotRoot))

	// Regression: a chain with a trailing blank line must not be mistaken for an
	// extra (empty) block, which previously errored out.
	_, gotRoot, err = splitRootCACertificate([]byte(root + "\n"))
	require.NoError(t, err)
	assert.Equal(t, 1, countCertBlocks(t, gotRoot))
}

// fakeInfisical serves the cert-manager endpoints the signer calls, returning the
// given JSON bodies for the create, poll, and bundle calls respectively.
func fakeInfisical(createBody, pollBody, bundleBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/applications/by-name/app"):
			_, _ = w.Write([]byte(`{"application":{"id":"app-id"}}`))
		case strings.HasSuffix(r.URL.Path, "/certificate-profiles/slug/prof"):
			_, _ = w.Write([]byte(`{"certificateProfile":{"id":"prof-id"}}`))
		case strings.Contains(r.URL.Path, "/certificate-requests/"):
			_, _ = w.Write([]byte(pollBody))
		case strings.HasSuffix(r.URL.Path, "/bundle"):
			_, _ = w.Write([]byte(bundleBody))
		default: // POST /api/v1/cert-manager/certificates
			_, _ = w.Write([]byte(createBody))
		}
	}))
}

func newTestSigner(url string) *signer {
	return &signer{spec: &v1alpha1.IssuerSpec{URL: url, Application: "app", Profile: "prof"}}
}

func TestSignerIssue(t *testing.T) {
	leaf := certPEM("leaf")
	cr := cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{Request: []byte("a-csr")}}

	tests := map[string]struct {
		createBody      string
		wantPending     bool
		wantRequestID   string
		wantTerminal    bool
		wantErr         bool
		wantCertificate bool
	}{
		"issued returns the certificate": {
			createBody:      fmt.Sprintf(`{"certificate":{"certificate":%q,"certificateChain":""}}`, leaf),
			wantCertificate: true,
		},
		"pending with a request id is polled later": {
			createBody:    `{"certificate":null,"certificateRequestId":"req-1","status":"pending"}`,
			wantPending:   true,
			wantRequestID: "req-1",
		},
		"synchronous failure on a 200 is terminal": {
			createBody:   `{"certificate":null,"status":"failed","message":"policy denied"}`,
			wantTerminal: true,
			wantErr:      true,
		},
		"no certificate and no request id is an error": {
			createBody: `{"certificate":null,"status":"","certificateRequestId":""}`,
			wantErr:    true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv := fakeInfisical(tc.createBody, "", "")
			defer srv.Close()

			s := newTestSigner(srv.URL)
			rest, err := s.restClient(context.Background(), "token")
			require.NoError(t, err)

			res, err := s.issue(context.Background(), rest, cr)
			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, tc.wantTerminal, IsTerminal(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantPending, res.Pending)
			assert.Equal(t, tc.wantRequestID, res.RequestID)
			assert.Equal(t, tc.wantCertificate, len(res.Certificate) > 0)
		})
	}
}

func TestCheckResponseClassification(t *testing.T) {
	tests := map[string]struct {
		code         int
		wantErr      bool
		wantTerminal bool
	}{
		"200 OK is not an error":              {code: http.StatusOK, wantErr: false},
		"400 Bad Request is terminal":         {code: http.StatusBadRequest, wantErr: true, wantTerminal: true},
		"403 Forbidden is terminal":           {code: http.StatusForbidden, wantErr: true, wantTerminal: true},
		"404 Not Found is terminal":           {code: http.StatusNotFound, wantErr: true, wantTerminal: true},
		"408 Request Timeout is transient":    {code: http.StatusRequestTimeout, wantErr: true, wantTerminal: false},
		"429 Too Many Requests is transient":  {code: http.StatusTooManyRequests, wantErr: true, wantTerminal: false},
		"500 Internal Server Error transient": {code: http.StatusInternalServerError, wantErr: true, wantTerminal: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()

			s := newTestSigner(srv.URL)
			rest, err := s.restClient(context.Background(), "token")
			require.NoError(t, err)

			res, err := rest.R().SetContext(context.Background()).Get("/")
			require.NoError(t, err)

			err = s.checkResponse(res, "act")
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.wantTerminal, IsTerminal(err), "terminal classification for status %d", tc.code)
		})
	}
}

func TestSignerPoll(t *testing.T) {
	leaf := certPEM("leaf")

	tests := map[string]struct {
		pollBody        string
		bundleBody      string
		wantPending     bool
		wantTerminal    bool
		wantErr         bool
		wantCertificate bool
	}{
		"issued fetches the bundle": {
			pollBody:        `{"status":"issued","certificateId":"cert-1"}`,
			bundleBody:      fmt.Sprintf(`{"certificate":%q,"certificateChain":null}`, leaf),
			wantCertificate: true,
		},
		"pending requeues":                            {pollBody: `{"status":"pending"}`, wantPending: true},
		"pending approval requeues":                   {pollBody: `{"status":"pending_approval"}`, wantPending: true},
		"pending validation requeues":                 {pollBody: `{"status":"pending_validation"}`, wantPending: true},
		"failed is terminal":                          {pollBody: `{"status":"failed","errorMessage":"bad"}`, wantTerminal: true, wantErr: true},
		"rejected is terminal":                        {pollBody: `{"status":"rejected"}`, wantTerminal: true, wantErr: true},
		"unknown status is terminal":                  {pollBody: `{"status":"surprise"}`, wantTerminal: true, wantErr: true},
		"issued without a certificate id is an error": {pollBody: `{"status":"issued"}`, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv := fakeInfisical("", tc.pollBody, tc.bundleBody)
			defer srv.Close()

			s := newTestSigner(srv.URL)
			rest, err := s.restClient(context.Background(), "token")
			require.NoError(t, err)

			res, err := s.poll(context.Background(), rest, "req-1")
			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, tc.wantTerminal, IsTerminal(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantPending, res.Pending)
			assert.Equal(t, tc.wantCertificate, len(res.Certificate) > 0)
		})
	}
}
