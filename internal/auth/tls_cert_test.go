package auth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/model"
)

func newClientKeyPairPEM(commonName string) (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).ToNot(HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).ToNot(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func tlsCertSpec(url, secretName, namespace string) *v1alpha1.IssuerSpec {
	spec := newIssuerSpec(v1alpha1.AuthMethodTLSCert)
	spec.URL = url
	spec.Authentication.TLSCert = &v1alpha1.TLSCertAuthConfig{
		IdentityIDRef:        v1alpha1.SecretReference{Name: secretName, Namespace: namespace, Key: "identityId"},
		ClientCertificateRef: v1alpha1.SecretReference{Name: secretName, Namespace: namespace, Key: "tls.crt"},
		ClientKeyRef:         v1alpha1.SecretReference{Name: secretName, Namespace: namespace, Key: "tls.key"},
	}
	return spec
}

var _ = Describe("TLS Certificate Auth", func() {
	const namespace = "default"

	It("should fail when .spec.authentication.tlsCert is nil", func() {
		err := auth.NewTLSCertAuth(k8sClient).Validate(ctx, newIssuerSpec(v1alpha1.AuthMethodTLSCert), namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(".spec.authentication.tlsCert is not set"))
	})

	It("should fail when the certificate and key do not form a key pair", func() {
		certPEM, _ := newClientKeyPairPEM("workload")
		_, otherKeyPEM := newClientKeyPairPEM("other")
		createSecret("tls-cert-mismatch", namespace, map[string][]byte{
			"identityId": []byte("identity-id"), "tls.crt": certPEM, "tls.key": otherKeyPEM,
		})
		DeferCleanup(func() { deleteSecret("tls-cert-mismatch", namespace) })

		err := auth.NewTLSCertAuth(k8sClient).Validate(ctx, tlsCertSpec("https://example.com", "tls-cert-mismatch", namespace), namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unable to load client certificate and key"))
	})

	It("should log in presenting the client certificate", func() {
		certPEM, keyPEM := newClientKeyPairPEM("workload")
		createSecret("tls-cert-login", namespace, map[string][]byte{
			"identityId": []byte("identity-id"), "tls.crt": certPEM, "tls.key": keyPEM,
		})
		DeferCleanup(func() { deleteSecret("tls-cert-login", namespace) })

		type loginRequest struct {
			path, presentedCN, identityID string
			decodeErr                     error
		}
		received := make(chan loginRequest, 1)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := loginRequest{path: r.URL.Path}
			if len(r.TLS.PeerCertificates) > 0 {
				got.presentedCN = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			var body map[string]string
			got.decodeErr = json.NewDecoder(r.Body).Decode(&body)
			got.identityID = body["identityId"]
			received <- got
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accessToken":"bound-token","expiresIn":600,"accessTokenMaxTTL":600,"tokenType":"Bearer"}`))
		}))
		server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
		server.StartTLS()
		DeferCleanup(server.Close)

		serverCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		result, err := auth.NewTLSCertAuth(k8sClient).Authenticate(ctx,
			&model.InfisicalConnection{Host: server.URL, CaCertificate: string(serverCA)},
			tlsCertSpec(server.URL, "tls-cert-login", namespace), namespace)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.AccessToken()).To(Equal("bound-token"))
		Expect(result.ClientCertificate).ToNot(BeNil())
		Expect(result.CredentialFingerprint).ToNot(BeEmpty())
		var got loginRequest
		Expect(received).To(Receive(&got))
		Expect(got.decodeErr).ToNot(HaveOccurred())
		Expect(got.path).To(Equal("/api/v1/auth/tls-cert-auth/login"))
		Expect(got.presentedCN).To(Equal("workload"))
		Expect(got.identityID).To(Equal("identity-id"))
	})

	It("should reject a plain http url", func() {
		err := auth.NewTLSCertAuth(k8sClient).Validate(ctx, tlsCertSpec("http://infisical.example.com", "unused", namespace), namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("requires an https:// url"))
	})

	DescribeTable("should fail login when Infisical does not return a token",
		func(status int, body, wantErr string) {
			certPEM, keyPEM := newClientKeyPairPEM("workload")
			secret := fmt.Sprintf("tls-cert-bad-login-%d", status)
			createSecret(secret, namespace, map[string][]byte{
				"identityId": []byte("identity-id"), "tls.crt": certPEM, "tls.key": keyPEM,
			})
			DeferCleanup(func() { deleteSecret(secret, namespace) })

			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			}))
			server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			server.StartTLS()
			DeferCleanup(server.Close)

			serverCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			_, err := auth.NewTLSCertAuth(k8sClient).Authenticate(ctx,
				&model.InfisicalConnection{Host: server.URL, CaCertificate: string(serverCA)},
				tlsCertSpec(server.URL, secret, namespace), namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(wantErr))
		},
		Entry("a 200 HTML page", http.StatusOK, "<html>login</html>", "returned no access token"),
		Entry("a 401 from Infisical", http.StatusUnauthorized, `{"message":"Certificate not allowed"}`, "Certificate not allowed"),
	)

	It("should log in again after the client certificate rotates", func() {
		certPEM, keyPEM := newClientKeyPairPEM("workload")
		createSecret("tls-cert-rotate", namespace, map[string][]byte{
			"identityId": []byte("identity-id"), "tls.crt": certPEM, "tls.key": keyPEM,
		})
		DeferCleanup(func() { deleteSecret("tls-cert-rotate", namespace) })

		var logins atomic.Int32
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logins.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accessToken":"bound-token","expiresIn":600,"accessTokenMaxTTL":600,"tokenType":"Bearer"}`))
		}))
		server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
		server.StartTLS()
		DeferCleanup(server.Close)

		authCache, err := cache.NewAuthCache(cache.WithMinTTLThreshold(time.Second))
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(authCache.Cleanup)

		caSecret := "tls-cert-rotate-ca"
		createSecret(caSecret, namespace, map[string][]byte{
			"ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		})
		DeferCleanup(func() { deleteSecret(caSecret, namespace) })

		spec := tlsCertSpec(server.URL, "tls-cert-rotate", namespace)
		spec.TLS = &v1alpha1.TLSConfig{CACertificate: v1alpha1.SecretReference{Name: caSecret, Namespace: namespace, Key: "ca.crt"}}
		resolver := auth.NewResolver(k8sClient, authCache, logr.Discard())
		key := cache.ClientCacheKey{Name: "rotating-issuer", Namespace: namespace}

		_, err = resolver.Authenticate(ctx, spec, key, namespace)
		Expect(err).ToNot(HaveOccurred())
		_, err = resolver.Authenticate(ctx, spec, key, namespace)
		Expect(err).ToNot(HaveOccurred())
		Expect(logins.Load()).To(BeEquivalentTo(1))

		By("rotating the certificate in the Secret")
		newCertPEM, newKeyPEM := newClientKeyPairPEM("workload")
		deleteSecret("tls-cert-rotate", namespace)
		createSecret("tls-cert-rotate", namespace, map[string][]byte{
			"identityId": []byte("identity-id"), "tls.crt": newCertPEM, "tls.key": newKeyPEM,
		})

		_, err = resolver.Authenticate(ctx, spec, key, namespace)
		Expect(err).ToNot(HaveOccurred())
		Expect(logins.Load()).To(BeEquivalentTo(2))
	})
})
