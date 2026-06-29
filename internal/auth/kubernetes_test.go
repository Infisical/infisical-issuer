package auth_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
)

var _ = Describe("Kubernetes Auth", func() {
	const (
		identityIDSecretName = "k8s-identity-id"
		namespace            = "default"
		secretKey            = "value"
	)

	It("should fail when .spec.authentication.kubernetes is nil", func() {
		provider := auth.NewKubernetesAuth(k8sClient)
		spec := newIssuerSpec(v1alpha1.AuthMethodKubernetes)

		err := provider.Validate(ctx, spec, namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(".spec.authentication.kubernetes is not set"))
	})

	It("should fail when serviceAccountRef name is empty", func() {
		provider := auth.NewKubernetesAuth(k8sClient)
		spec := newIssuerSpec(v1alpha1.AuthMethodKubernetes)
		spec.Authentication.Kubernetes = &v1alpha1.KubernetesAuthConfig{
			ServiceAccountRef: v1alpha1.NamespacedName{Name: "", Namespace: namespace},
		}

		err := provider.Validate(ctx, spec, namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("serviceAccountRef requires a name"))
	})

	It("should fail when the identity id secret does not exist", func() {
		provider := auth.NewKubernetesAuth(k8sClient)
		spec := newIssuerSpec(v1alpha1.AuthMethodKubernetes)
		spec.Authentication.Kubernetes = &v1alpha1.KubernetesAuthConfig{
			ServiceAccountRef: v1alpha1.NamespacedName{Name: "my-sa", Namespace: namespace},
			IdentityIDRef:     v1alpha1.SecretReference{Name: identityIDSecretName, Namespace: namespace, Key: secretKey},
		}

		err := provider.Validate(ctx, spec, namespace)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unable to fetch secret"))
	})

	It("should succeed when serviceAccountRef and the identity id secret are set", func() {
		createSecret(identityIDSecretName, namespace, map[string][]byte{secretKey: []byte("my-identity-id")})
		DeferCleanup(func() { deleteSecret(identityIDSecretName, namespace) })

		provider := auth.NewKubernetesAuth(k8sClient)
		spec := newIssuerSpec(v1alpha1.AuthMethodKubernetes)
		spec.Authentication.Kubernetes = &v1alpha1.KubernetesAuthConfig{
			ServiceAccountRef: v1alpha1.NamespacedName{Name: "my-sa", Namespace: namespace},
			IdentityIDRef:     v1alpha1.SecretReference{Name: identityIDSecretName, Namespace: namespace, Key: secretKey},
		}

		Expect(provider.Validate(ctx, spec, namespace)).To(Succeed())
	})
})
