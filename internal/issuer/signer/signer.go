package signer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
	"github.com/Infisical/infisical-issuer/internal/cache"
	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-resty/resty/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	statusIssued            = "issued"
	statusFailed            = "failed"
	statusReject            = "rejected"
	statusPending           = "pending"
	statusPendingApproval   = "pending_approval"
	statusPendingValidation = "pending_validation"
)

type HealthChecker interface {
	Check(ctx context.Context) error
}

type Signer interface {
	Sign(ctx context.Context, cr certmanager.CertificateRequest, priorRequestID string) (SignResult, error)
}

type SignResult struct {
	Certificate    []byte
	CA             []byte
	Pending        bool
	RequestID      string
	PendingMessage string
}

type HealthCheckerBuilder func(c client.Client, resolver *auth.Resolver, spec *v1alpha1.IssuerSpec, key cache.ClientCacheKey, resourceNamespace string) (HealthChecker, error)

type Builder func(c client.Client, resolver *auth.Resolver, spec *v1alpha1.IssuerSpec, key cache.ClientCacheKey, resourceNamespace string) (Signer, error)

type signer struct {
	resolver *auth.Resolver
	spec     *v1alpha1.IssuerSpec
	key      cache.ClientCacheKey
	// resourceNamespace is the namespace credential references must resolve within.
	resourceNamespace string
}

func NewHealthChecker(_ client.Client, resolver *auth.Resolver, spec *v1alpha1.IssuerSpec, key cache.ClientCacheKey, resourceNamespace string) (HealthChecker, error) {
	return &signer{resolver: resolver, spec: spec, key: key, resourceNamespace: resourceNamespace}, nil
}

func New(_ client.Client, resolver *auth.Resolver, spec *v1alpha1.IssuerSpec, key cache.ClientCacheKey, resourceNamespace string) (Signer, error) {
	return &signer{resolver: resolver, spec: spec, key: key, resourceNamespace: resourceNamespace}, nil
}

func (s *signer) restClient(ctx context.Context, token string) (*resty.Client, error) {
	c := resty.New().
		SetBaseURL(s.spec.URL).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json")

	if s.spec.TLS != nil {
		conn, err := s.resolver.Connection(ctx, s.spec, s.resourceNamespace)
		if err != nil {
			return nil, err
		}
		// Append the configured CA to the system roots rather than replacing them.
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(conn.CaCertificate)) {
			return nil, fmt.Errorf("no valid certificates found in tls.caCertificate")
		}
		c.SetTLSClientConfig(&tls.Config{RootCAs: pool})
	}
	return c, nil
}

func (s *signer) authedClient(ctx context.Context) (*resty.Client, error) {
	result, err := s.resolver.Authenticate(ctx, s.spec, s.key, s.resourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("authenticating with Infisical: %w", err)
	}
	return s.restClient(ctx, result.AccessToken())
}

type terminalError struct{ msg string }

func (e *terminalError) Error() string { return e.msg }

func IsTerminal(err error) bool {
	var t *terminalError
	return errors.As(err, &t)
}

// NewTerminalErrorForTesting lets other packages' tests build a terminal error
// without a real API call.
func NewTerminalErrorForTesting(msg string) error {
	return &terminalError{msg: msg}
}

// checkResponse classifies a response: 401 (which also invalidates the cached
// token), 408, 429, and 5xx/transport errors are transient; other 4xx are terminal.
func (s *signer) checkResponse(res *resty.Response, action string) error {
	code := res.StatusCode()
	if code == http.StatusUnauthorized {
		s.resolver.Invalidate(s.key)
		return fmt.Errorf("%s: %s", action, res.String())
	}
	if !res.IsError() {
		return nil
	}
	if code == http.StatusRequestTimeout || code == http.StatusTooManyRequests {
		return fmt.Errorf("%s: %s", action, res.String())
	}
	if code >= 400 && code < 500 {
		return &terminalError{msg: fmt.Sprintf("%s: %s", action, res.String())}
	}
	return fmt.Errorf("%s: %s", action, res.String())
}

func (s *signer) Check(ctx context.Context) error {
	rest, err := s.authedClient(ctx)
	if err != nil {
		return err
	}
	if _, err := s.resolveApplicationID(ctx, rest); err != nil {
		return err
	}
	if _, err := s.resolveProfileID(ctx, rest); err != nil {
		return err
	}
	return nil
}

func (s *signer) Sign(ctx context.Context, cr certmanager.CertificateRequest, priorRequestID string) (SignResult, error) {
	rest, err := s.authedClient(ctx)
	if err != nil {
		return SignResult{}, err
	}
	if priorRequestID != "" {
		return s.poll(ctx, rest, priorRequestID)
	}
	return s.issue(ctx, rest, cr)
}

type createCertAttributes struct {
	TTL string `json:"ttl,omitempty"`
}

type createCertRequest struct {
	ProfileID     string                `json:"profileId"`
	ApplicationID string                `json:"applicationId,omitempty"`
	Csr           string                `json:"csr"`
	Attributes    *createCertAttributes `json:"attributes,omitempty"`
}

type issuedCertificate struct {
	Certificate      string `json:"certificate"`
	CertificateChain string `json:"certificateChain"`
}

type createCertResponse struct {
	Certificate          *issuedCertificate `json:"certificate"`
	CertificateRequestID string             `json:"certificateRequestId"`
	Status               string             `json:"status"`
	Message              string             `json:"message"`
}

func (s *signer) issue(ctx context.Context, rest *resty.Client, cr certmanager.CertificateRequest) (SignResult, error) {
	applicationID, err := s.resolveApplicationID(ctx, rest)
	if err != nil {
		return SignResult{}, err
	}
	profileID, err := s.resolveProfileID(ctx, rest)
	if err != nil {
		return SignResult{}, err
	}

	body := createCertRequest{
		ProfileID:     profileID,
		ApplicationID: applicationID,
		Csr:           string(cr.Spec.Request),
	}
	if cr.Spec.Duration != nil {
		// Infisical's TTL granularity is whole hours ("m" means months), so
		// truncate down to whole hours with a one-hour floor.
		hours := int(cr.Spec.Duration.Hours())
		if hours < 1 {
			hours = 1
		}
		body.Attributes = &createCertAttributes{TTL: fmt.Sprintf("%dh", hours)}
	}

	var out createCertResponse
	res, err := rest.R().
		SetContext(ctx).
		SetBody(body).
		SetResult(&out).
		Post("/api/v1/cert-manager/certificates")
	if err != nil {
		return SignResult{}, err
	}
	if err := s.checkResponse(res, "sign request rejected by Infisical"); err != nil {
		return SignResult{}, err
	}

	if out.Certificate != nil {
		return assemble(out.Certificate.Certificate, out.Certificate.CertificateChain)
	}

	// No certificate in the response: a 2xx can still carry a terminal status, and
	// without a request id we cannot poll, so treat that as an error rather than
	// silently re-issuing a new request every reconcile.
	if out.Status == statusFailed || out.Status == statusReject {
		return SignResult{}, &terminalError{msg: fmt.Sprintf("Infisical returned status %q for the sign request: %s", out.Status, out.Message)}
	}
	if out.CertificateRequestID == "" {
		return SignResult{}, errors.New("sign response had no certificate and no request id to poll")
	}
	return SignResult{
		Pending:        true,
		RequestID:      out.CertificateRequestID,
		PendingMessage: pendingMessage(out.Message),
	}, nil
}

type pollResponse struct {
	Status         string  `json:"status"`
	CertificateID  *string `json:"certificateId"`
	ErrorMessage   *string `json:"errorMessage"`
	PendingMessage *string `json:"pendingMessage"`
}

func (s *signer) poll(ctx context.Context, rest *resty.Client, requestID string) (SignResult, error) {
	var out pollResponse
	res, err := rest.R().
		SetContext(ctx).
		SetResult(&out).
		Get("/api/v1/cert-manager/certificates/certificate-requests/" + requestID)
	if err != nil {
		return SignResult{}, err
	}
	if err := s.checkResponse(res, "checking certificate request status"); err != nil {
		return SignResult{}, err
	}

	switch out.Status {
	case statusIssued:
		if out.CertificateID == nil {
			return SignResult{}, fmt.Errorf("certificate request %s issued but returned no certificate id", requestID)
		}
		return s.bundle(ctx, rest, *out.CertificateID)
	case statusFailed, statusReject:
		return SignResult{}, &terminalError{msg: fmt.Sprintf("certificate request %s %s: %s", requestID, out.Status, deref(out.ErrorMessage))}
	case statusPending, statusPendingApproval, statusPendingValidation:
		return SignResult{Pending: true, RequestID: requestID, PendingMessage: pendingMessage(deref(out.PendingMessage))}, nil
	default:
		// Unknown status is terminal; every in-progress status is enumerated above.
		return SignResult{}, &terminalError{msg: fmt.Sprintf("certificate request %s returned unexpected status %q", requestID, out.Status)}
	}
}

type bundleResponse struct {
	Certificate      string  `json:"certificate"`
	CertificateChain *string `json:"certificateChain"`
}

func (s *signer) bundle(ctx context.Context, rest *resty.Client, certificateID string) (SignResult, error) {
	var out bundleResponse
	res, err := rest.R().
		SetContext(ctx).
		SetResult(&out).
		Get("/api/v1/cert-manager/certificates/" + certificateID + "/bundle")
	if err != nil {
		return SignResult{}, err
	}
	if err := s.checkResponse(res, "fetching certificate bundle"); err != nil {
		return SignResult{}, err
	}
	chain := ""
	if out.CertificateChain != nil {
		chain = *out.CertificateChain
	}
	return assemble(out.Certificate, chain)
}

type applicationByNameResponse struct {
	Application struct {
		ID string `json:"id"`
	} `json:"application"`
}

func (s *signer) resolveApplicationID(ctx context.Context, rest *resty.Client) (string, error) {
	var out applicationByNameResponse
	res, err := rest.R().
		SetContext(ctx).
		SetPathParam("name", s.spec.Application).
		SetResult(&out).
		Get("/api/v1/cert-manager/applications/by-name/{name}")
	if err != nil {
		return "", err
	}
	if err := s.checkResponse(res, fmt.Sprintf("looking up application %q", s.spec.Application)); err != nil {
		return "", err
	}
	if out.Application.ID == "" {
		return "", fmt.Errorf("application %q not found", s.spec.Application)
	}
	return out.Application.ID, nil
}

type profileBySlugResponse struct {
	CertificateProfile struct {
		ID string `json:"id"`
	} `json:"certificateProfile"`
}

func (s *signer) resolveProfileID(ctx context.Context, rest *resty.Client) (string, error) {
	var out profileBySlugResponse
	res, err := rest.R().
		SetContext(ctx).
		SetPathParam("slug", s.spec.Profile).
		SetResult(&out).
		Get("/api/v1/cert-manager/certificate-profiles/slug/{slug}")
	if err != nil {
		return "", err
	}
	if err := s.checkResponse(res, fmt.Sprintf("looking up profile %q", s.spec.Profile)); err != nil {
		return "", err
	}
	if out.CertificateProfile.ID == "" {
		return "", fmt.Errorf("profile %q not found", s.spec.Profile)
	}
	return out.CertificateProfile.ID, nil
}

func assemble(leaf, chain string) (SignResult, error) {
	if leaf == "" {
		return SignResult{}, errors.New("issued certificate from Infisical was empty")
	}
	certPem := []byte(leaf)
	if len(certPem) > 0 && certPem[len(certPem)-1] != '\n' {
		certPem = append(certPem, '\n')
	}
	if chain == "" {
		return SignResult{Certificate: certPem}, nil
	}
	intermediates, root, err := splitRootCACertificate([]byte(chain))
	if err != nil {
		return SignResult{}, err
	}
	certPem = append(certPem, intermediates...)
	return SignResult{Certificate: certPem, CA: root}, nil
}

func pendingMessage(msg string) string {
	if msg == "" {
		return "Infisical has accepted the request and it is awaiting issuance"
	}
	return msg
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func splitRootCACertificate(chainPEM []byte) (intermediates []byte, root []byte, err error) {
	var blocks [][]byte
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM block %q in certificate chain", block.Type)
		}
		blocks = append(blocks, pem.EncodeToMemory(block))
	}
	if len(blocks) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in certificate chain")
	}
	for _, b := range blocks[:len(blocks)-1] {
		intermediates = append(intermediates, b...)
	}
	root = blocks[len(blocks)-1]
	return intermediates, root, nil
}
