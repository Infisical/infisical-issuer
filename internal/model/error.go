package model

import "errors"

var (
	ErrInvalidIssuerSpec     = errors.New("invalid issuer spec")
	ErrUnsupportedAuthMethod = errors.New("unsupported authentication method")
)
