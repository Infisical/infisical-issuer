package signer

import (
	"encoding/pem"
	"time"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/go-resty/resty/v2"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*v1alpha1.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign([]byte) ([]byte, error)
}

type SignerBuilder func(*v1alpha1.IssuerSpec, map[string][]byte) (Signer, error)

func ExampleHealthCheckerFromIssuerAndSecretData(*v1alpha1.IssuerSpec, map[string][]byte) (HealthChecker, error) {
	return &exampleSigner{}, nil
}

func ExampleSignerFromIssuerAndSecretData(spec *v1alpha1.IssuerSpec, secretData map[string][]byte) (Signer, error) {
	clientSecret := string(secretData["clientSecret"]) // Extract clientSecret from secretData
	
	return &exampleSigner{
		siteUrl: spec.URL,
		caId:    spec.CaId,
		clientId:     spec.Authentication.UniversalAuth.ClientId,
		clientSecret: clientSecret,
	}, nil
}

type exampleSigner struct {
	siteUrl string
	caId    string
	clientId string
	clientSecret string
}

func (o *exampleSigner) Check() error {
	// TODO (dangtony98): Implement health check
	return nil
}

var (
	duration = time.Hour * 24 * 365
)

type AuthResponse struct {
	AccessToken       string `json:"accessToken"`
	ExpiresIn         int    `json:"expiresIn"`
	AccessTokenMaxTTL int    `json:"accessTokenMaxTTL"`
	TokenType         string `json:"tokenType"`
}

type SignCertificateResponse struct {
	Certificate          string `json:"certificate"`
	CertificateChain     string `json:"certificateChain"`
	IssuingCaCertificate string `json:"issuingCaCertificate"`
	SerialNumber         string `json:"serialNumber"`
}

type SignCertificateRequest struct {
	CaId                  string  `json:"caId,omitempty"`                  // Optional, use pointer to indicate optional fields
	CertificateTemplateId *string `json:"certificateTemplateId,omitempty"` // Optional
	PkiCollectionId       *string `json:"pkiCollectionId,omitempty"`       // Optional
	Csr                   string  `json:"csr"`                             // Required
	FriendlyName          *string `json:"friendlyName,omitempty"`          // Optional
	CommonName            string  `json:"commonName,omitempty"`            // Optional
	Ttl                   string  `json:"ttl,omitempty"`                   // Optional
	NotBefore             *string `json:"notBefore,omitempty"`             // Optional
	NotAfter              *string `json:"notAfter,omitempty"`              // Optional
}

func (o *exampleSigner) Sign(csrBytes []byte) ([]byte, error) {
	client := resty.New()

	authResponse := AuthResponse{}
	signCertificateResponse := SignCertificateResponse{}

	// Login operation against Infisical
	_, err := client.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetFormData(map[string]string{
			"clientId":     o.clientId,
			"clientSecret": o.clientSecret,
		}).
		SetResult(&authResponse).
		Post(o.siteUrl + "/api/v1/auth/universal-auth/login")

	// Check for errors
	if err != nil {
		return nil, err
	}

	// NOTE (dangtony98): Take TTL from spec
	// Define the request body based on your CSR
	requestBody := SignCertificateRequest{
		CaId:                  o.caId,           // This field is optional, so it can be nil
		CertificateTemplateId: nil,              // Optional
		PkiCollectionId:       nil,              // Optional
		Csr:                   string(csrBytes), // Required
		FriendlyName:          nil,              // Optional
		CommonName:            "example.com",    // Optional
		Ttl:                   "3d",             // Optional
		NotBefore:             nil,              // Optional
		NotAfter:              nil,              // Optional
	}

	// Make the POST request with Bearer token authentication and JSON body
	_, err = client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+authResponse.AccessToken).
		SetBody(requestBody).
		SetResult(&signCertificateResponse).
		Post(o.siteUrl + "/api/v1/pki/certificates/sign-certificate")

	certificate := signCertificateResponse.Certificate
	block, _ := pem.Decode([]byte(certificate)) 
	pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: block.Bytes,
	})

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: block.Bytes,
	}), nil
}
