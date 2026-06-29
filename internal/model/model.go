package model

import (
	infisical "github.com/infisical/go-sdk"
)

type InfisicalConnection struct {
	Host          string
	CaCertificate string
}

type AuthenticationResult struct {
	MachineIdentity infisical.MachineIdentityCredential
}

func (a *AuthenticationResult) AccessToken() string {
	return a.MachineIdentity.AccessToken
}
