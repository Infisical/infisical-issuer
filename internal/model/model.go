package model

import (
	"crypto/tls"

	infisical "github.com/infisical/go-sdk"
)

type InfisicalConnection struct {
	Host          string
	CaCertificate string
}

type AuthenticationResult struct {
	MachineIdentity infisical.MachineIdentityCredential
	// ClientCertificate is presented on every API call when set.
	ClientCertificate *tls.Certificate
	// CredentialFingerprint identifies the credential the token was obtained with;
	// a cached result is discarded once the current credential no longer matches it.
	CredentialFingerprint string
}

func (a *AuthenticationResult) AccessToken() string {
	return a.MachineIdentity.AccessToken
}
