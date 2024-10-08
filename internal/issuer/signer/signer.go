package signer

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-resty/resty/v2"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*v1alpha1.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(certmanager.CertificateRequest) ([]byte, []byte, error)
}

type SignerBuilder func(*v1alpha1.IssuerSpec, map[string][]byte) (Signer, error)

func HealthCheckerFromIssuerAndSecretData(spec *v1alpha1.IssuerSpec, secretData map[string][]byte) (HealthChecker, error) {
	return &signer{
		siteUrl:               spec.URL,
		caId:                  spec.CaId,
		clientId:              spec.Authentication.UniversalAuth.ClientId,
		certificateTemplateId: spec.CertificateTemplateId,
		clientSecret:          string(secretData["clientSecret"]),
	}, nil
}

func SignerFromIssuerAndSecretData(spec *v1alpha1.IssuerSpec, secretData map[string][]byte) (Signer, error) {
	return &signer{
		siteUrl:               spec.URL,
		caId:                  spec.CaId,
		certificateTemplateId: spec.CertificateTemplateId,
		clientId:              spec.Authentication.UniversalAuth.ClientId,
		clientSecret:          string(secretData["clientSecret"]),
	}, nil
}

type signer struct {
	siteUrl               string
	caId                  string
	certificateTemplateId string
	clientId              string
	clientSecret          string
}

func (o *signer) Check() error {
	client := resty.New()

	// Perform the GET request to the health check endpoint
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		Get(o.siteUrl + "/api/status")

	// Check if there was an error making the request
	if err != nil {
		return fmt.Errorf("Failed to check health of signer: %w", err)
	}

	// Check the HTTP status code returned by the server
	if resp.StatusCode() != 200 {
		return fmt.Errorf("Health check failed: received status code %d, response: %s", resp.StatusCode(), resp.String())
	}

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

type SignCertificateRequest struct {
	CaId                  string `json:"caId,omitempty"`
	CertificateTemplateId string `json:"certificateTemplateId,omitempty"`
	Csr                   string `json:"csr"`
	Ttl                   string `json:"ttl,omitempty"`
}

type SignCertificateResponse struct {
	Certificate          string `json:"certificate"`
	CertificateChain     string `json:"certificateChain"`
	IssuingCaCertificate string `json:"issuingCaCertificate"`
	SerialNumber         string `json:"serialNumber"`
}

func (o *signer) Sign(cr certmanager.CertificateRequest) ([]byte, []byte, error) {

	// Ensure either caId or certificateTemplateId is provided
	if o.caId == "" && o.certificateTemplateId == "" {
		return nil, nil, fmt.Errorf("Either caId or certificateTemplateId must be provided")
	}

	csrBytes := cr.Spec.Request
	// csr, err := parseCSR(csrBytes)
	// if err != nil {
	//     return nil, err
	// }

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
		return nil, nil, err
	}

	// Define the request body based on your CSR
	requestBody := SignCertificateRequest{
		Csr: string(csrBytes), // Required
		Ttl: "90d",            // Default ttl
	}

	if o.caId != "" {
		requestBody.CaId = o.caId
	}
	if o.certificateTemplateId != "" {
		requestBody.CertificateTemplateId = o.certificateTemplateId
	}

	if cr.Spec.Duration != nil {
		requestBody.Ttl = fmt.Sprintf("%ds", int(cr.Spec.Duration.Duration.Seconds()))
	}

	// Make the POST request with Bearer token authentication and JSON body
	_, err = client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+authResponse.AccessToken).
		SetBody(requestBody).
		SetResult(&signCertificateResponse).
		Post(o.siteUrl + "/api/v1/pki/certificates/sign-certificate")

	certificate := signCertificateResponse.Certificate // Leaf certificate
	chainPem := signCertificateResponse.CertificateChain // Full chain (intermediate certs + root cert)

	caChainCerts, rootCACert, err := splitRootCACertificate([]byte(chainPem))
	certPem := []byte(certificate + "\n")
	certPem = append(certPem, caChainCerts...)

	return certPem, rootCACert, nil
}

func splitRootCACertificate(caCertChainPem []byte) ([]byte, []byte, error) {
	var caChainCerts []byte
	var rootCACert []byte
	for {
		block, rest := pem.Decode(caCertChainPem)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("failed to read certificate")
		}
		var encBuf bytes.Buffer
		if err := pem.Encode(&encBuf, block); err != nil {
			return nil, nil, err
		}
		if len(rest) > 0 {
			caChainCerts = append(caChainCerts, encBuf.Bytes()...)
			caCertChainPem = rest
		} else {
			rootCACert = append(rootCACert, encBuf.Bytes()...)
			break
		}
	}
	return caChainCerts, rootCACert, nil
}
