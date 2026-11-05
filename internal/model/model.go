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
	MachineIdentity   infisical.MachineIdentityCredential
	ClientCertificate *tls.Certificate
	// Cached results are dropped when this no longer matches the live credential.
	CredentialFingerprint string
}

func (a *AuthenticationResult) AccessToken() string {
	return a.MachineIdentity.AccessToken
}
