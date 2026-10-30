package auth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/model"
	"github.com/Infisical/infisical-issuer/internal/util"
	"github.com/go-resty/resty/v2"
	infisical "github.com/infisical/go-sdk"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const tlsCertAuthLoginPath = "/api/v1/auth/tls-cert-auth/login"

type tlsCertAuth struct {
	client client.Client
}

func NewTLSCertAuth(c client.Client) Strategy {
	return &tlsCertAuth{client: c}
}

func (t *tlsCertAuth) config(spec *v1alpha1.IssuerSpec) (*v1alpha1.TLSCertAuthConfig, error) {
	cfg := spec.Authentication.TLSCert
	if cfg == nil {
		return nil, fmt.Errorf("%w: method is %q but .spec.authentication.tlsCert is not set", model.ErrInvalidIssuerSpec, v1alpha1.AuthMethodTLSCert)
	}
	return cfg, nil
}

func (t *tlsCertAuth) loadKeyPair(ctx context.Context, cfg *v1alpha1.TLSCertAuthConfig, resourceNamespace string) (*tls.Certificate, error) {
	certPEM, err := util.ResolveSecretReference(ctx, t.client, cfg.ClientCertificateRef, resourceNamespace, ".spec.authentication.tlsCert.clientCertificateRef")
	if err != nil {
		return nil, err
	}
	keyPEM, err := util.ResolveSecretReference(ctx, t.client, cfg.ClientKeyRef, resourceNamespace, ".spec.authentication.tlsCert.clientKeyRef")
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("%w: unable to load client certificate and key: %v", model.ErrInvalidIssuerSpec, err)
	}
	return &pair, nil
}

func certificateFingerprint(pair *tls.Certificate) string {
	sum := sha256.Sum256(pair.Certificate[0])
	return hex.EncodeToString(sum[:])
}

func (t *tlsCertAuth) Validate(ctx context.Context, spec *v1alpha1.IssuerSpec, resourceNamespace string) error {
	cfg, err := t.config(spec)
	if err != nil {
		return err
	}
	if _, err := util.ResolveSecretReference(ctx, t.client, cfg.IdentityIDRef, resourceNamespace, ".spec.authentication.tlsCert.identityIdRef"); err != nil {
		return err
	}
	_, err = t.loadKeyPair(ctx, cfg, resourceNamespace)
	return err
}

func (t *tlsCertAuth) Fingerprint(ctx context.Context, spec *v1alpha1.IssuerSpec, resourceNamespace string) (string, error) {
	cfg, err := t.config(spec)
	if err != nil {
		return "", err
	}
	pair, err := t.loadKeyPair(ctx, cfg, resourceNamespace)
	if err != nil {
		return "", err
	}
	return certificateFingerprint(pair), nil
}

type tlsCertAuthLoginRequest struct {
	IdentityID string `json:"identityId"`
}

func (t *tlsCertAuth) Authenticate(ctx context.Context, conn *model.InfisicalConnection, spec *v1alpha1.IssuerSpec, resourceNamespace string) (*model.AuthenticationResult, error) {
	cfg, err := t.config(spec)
	if err != nil {
		return nil, err
	}
	identityID, err := util.ResolveSecretReference(ctx, t.client, cfg.IdentityIDRef, resourceNamespace, ".spec.authentication.tlsCert.identityIdRef")
	if err != nil {
		return nil, err
	}
	pair, err := t.loadKeyPair(ctx, cfg, resourceNamespace)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := util.NewTLSConfig(conn.CaCertificate, pair)
	if err != nil {
		return nil, err
	}

	var cred infisical.MachineIdentityCredential
	res, err := resty.New().
		SetTLSClientConfig(tlsConfig).
		R().
		SetContext(ctx).
		SetBody(tlsCertAuthLoginRequest{IdentityID: identityID}).
		SetResult(&cred).
		Post(strings.TrimRight(conn.Host, "/") + tlsCertAuthLoginPath)
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate with TLS Certificate Auth: %w", err)
	}
	if res.IsError() {
		return nil, fmt.Errorf("unable to authenticate with TLS Certificate Auth: %s: %s", res.Status(), res.String())
	}

	return &model.AuthenticationResult{
		MachineIdentity:       cred,
		ClientCertificate:     pair,
		CredentialFingerprint: certificateFingerprint(pair),
	}, nil
}
