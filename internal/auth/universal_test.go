package auth_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
)

var _ = Describe("Universal Auth", func() {
	const (
		clientIDSecretName     = "universal-client-id"
		clientSecretSecretName = "universal-client-secret"
		namespace              = "default"
		secretKey              = "value"
	)

	It("should fail when .spec.authentication.universal is nil", func() {
		provider := auth.NewUniversalAuth(k8sClient)
		spec := newIssuerSpec(v1alpha1.AuthMethodUniversal)

		err := provider.Validate(ctx, spec, namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(".spec.authentication.universal is not set"))
	})

	It("should fail when the referenced secrets do not exist", func() {
		provider := auth.NewUniversalAuth(k8sClient)
		spec := newIssuerSpec(v1alpha1.AuthMethodUniversal)
		spec.Authentication.Universal = &v1alpha1.UniversalAuthConfig{
			ClientIDRef:     v1alpha1.SecretReference{Name: clientIDSecretName, Namespace: namespace, Key: secretKey},
			ClientSecretRef: v1alpha1.SecretReference{Name: clientSecretSecretName, Namespace: namespace, Key: secretKey},
		}

		err := provider.Validate(ctx, spec, namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unable to fetch secret"))
	})

	It("should succeed when both secrets exist, then fail after deletion", func() {
		By("creating the required secrets")
		createSecret(clientIDSecretName, namespace, map[string][]byte{secretKey: []byte("my-client-id")})
		createSecret(clientSecretSecretName, namespace, map[string][]byte{secretKey: []byte("my-client-secret")})

		provider := auth.NewUniversalAuth(k8sClient)
		spec := newIssuerSpec(v1alpha1.AuthMethodUniversal)
		spec.Authentication.Universal = &v1alpha1.UniversalAuthConfig{
			ClientIDRef:     v1alpha1.SecretReference{Name: clientIDSecretName, Namespace: namespace, Key: secretKey},
			ClientSecretRef: v1alpha1.SecretReference{Name: clientSecretSecretName, Namespace: namespace, Key: secretKey},
		}

		By("validating, which should succeed")
		Expect(provider.Validate(ctx, spec, namespace)).To(Succeed())

		By("deleting the secrets")
		deleteSecret(clientIDSecretName, namespace)
		deleteSecret(clientSecretSecretName, namespace)

		By("validating again, which should fail")
		err := provider.Validate(ctx, spec, namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unable to fetch secret"))
	})

	It("should fail when the secret exists but the key is missing", func() {
		secretName := "universal-wrong-key"
		createSecret(secretName, namespace, map[string][]byte{"wrong-key": []byte("data")})
		DeferCleanup(func() { deleteSecret(secretName, namespace) })

		provider := auth.NewUniversalAuth(k8sClient)
		spec := newIssuerSpec(v1alpha1.AuthMethodUniversal)
		spec.Authentication.Universal = &v1alpha1.UniversalAuthConfig{
			ClientIDRef:     v1alpha1.SecretReference{Name: secretName, Namespace: namespace, Key: secretKey},
			ClientSecretRef: v1alpha1.SecretReference{Name: secretName, Namespace: namespace, Key: secretKey},
		}

		err := provider.Validate(ctx, spec, namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no value for key"))
	})
})
