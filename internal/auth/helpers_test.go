package auth_test

import (
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
)

func createSecret(name, namespace string, data map[string][]byte) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       data,
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
}

func deleteSecret(name, namespace string) {
	secret := &corev1.Secret{}
	Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, secret)).To(Succeed())
	Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
}

func newIssuerSpec(method v1alpha1.AuthMethod) *v1alpha1.IssuerSpec {
	return &v1alpha1.IssuerSpec{
		URL:            "https://app.infisical.com",
		Application:    "app",
		Profile:        "profile",
		Authentication: v1alpha1.Authentication{Method: method},
	}
}
