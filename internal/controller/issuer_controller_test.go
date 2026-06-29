package controller

import (
	"context"
	"errors"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	issuerapi "github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/issuer/signer"
)

type fakeHealthChecker struct{ err error }

func (f *fakeHealthChecker) Check(_ context.Context) error { return f.err }

func fakeHealthCheckerBuilder(checkErr error) signer.HealthCheckerBuilder {
	return func(client.Client, *auth.Resolver, *issuerapi.IssuerSpec, cache.ClientCacheKey, string) (signer.HealthChecker, error) {
		return &fakeHealthChecker{err: checkErr}, nil
	}
}

var _ = Describe("Issuer Controller", func() {
	const namespace = "default"

	var reconciler *IssuerReconciler

	// newReconciler builds an IssuerReconciler whose health check result is
	// controlled by checkErr, with a real auth resolver so Validate runs against
	// the envtest API server.
	newReconciler := func(checkErr error) *IssuerReconciler {
		authCache, err := cache.NewAuthCache()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(authCache.Cleanup)

		return &IssuerReconciler{
			Kind:                 "Issuer",
			Client:               k8sClient,
			Scheme:               k8sClient.Scheme(),
			HealthCheckerBuilder: fakeHealthCheckerBuilder(checkErr),
			AuthResolver:         auth.NewResolver(k8sClient, authCache, logr.Discard()),
			recorder:             record.NewFakeRecorder(100),
		}
	}

	// createIssuer creates a Universal-auth Issuer referencing the given secret.
	createIssuer := func(name, credentialsSecret string) types.NamespacedName {
		issuer := &issuerapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: issuerapi.IssuerSpec{
				URL:         "https://app.infisical.com",
				Application: "app",
				Profile:     "profile",
				Authentication: issuerapi.Authentication{
					Method: issuerapi.AuthMethodUniversal,
					Universal: &issuerapi.UniversalAuthConfig{
						ClientIDRef:     issuerapi.SecretReference{Name: credentialsSecret, Namespace: namespace, Key: "clientId"},
						ClientSecretRef: issuerapi.SecretReference{Name: credentialsSecret, Namespace: namespace, Key: "clientSecret"},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, issuer)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, issuer))).To(Succeed()) })
		return types.NamespacedName{Name: name, Namespace: namespace}
	}

	createCredentialsSecret := func(name string) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Data: map[string][]byte{
				"clientId":     []byte("a-client-id"),
				"clientSecret": []byte("a-client-secret"),
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, secret))).To(Succeed()) })
	}

	readyCondition := func(name types.NamespacedName) *metav1.Condition {
		issuer := &issuerapi.Issuer{}
		Expect(k8sClient.Get(ctx, name, issuer)).To(Succeed())
		return meta.FindStatusCondition(issuer.Status.Conditions, issuerapi.ConditionReady)
	}

	// reconcileOnce runs a single reconcile; errors are surfaced through the Ready
	// condition, which the caller asserts.
	reconcileOnce := func(name types.NamespacedName) {
		_, _ = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
	}

	It("sets Ready=Unknown with reason 'First seen' on the first reconcile", func() {
		reconciler = newReconciler(nil)
		name := createIssuer("issuer-first-seen", "missing-secret")

		reconcileOnce(name)

		cond := readyCondition(name)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionUnknown))
		Expect(cond.Message).To(Equal("First seen"))
	})

	It("sets Ready=False when the referenced auth secret is missing", func() {
		reconciler = newReconciler(nil)
		name := createIssuer("issuer-bad-secret", "does-not-exist")

		reconcileOnce(name) // First seen
		reconcileOnce(name) // Validate fails

		cond := readyCondition(name)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Message).To(ContainSubstring("unable to fetch secret"))
	})

	It("sets Ready=True when validation and the health check both succeed", func() {
		reconciler = newReconciler(nil)
		createCredentialsSecret("issuer-good-credentials")
		name := createIssuer("issuer-ready", "issuer-good-credentials")

		reconcileOnce(name) // First seen
		reconcileOnce(name) // Validate + Check

		cond := readyCondition(name)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(cond.Message).To(Equal("Success"))
	})

	It("sets Ready=False when the health check fails", func() {
		reconciler = newReconciler(errors.New("cannot reach Infisical"))
		createCredentialsSecret("issuer-healthcheck-credentials")
		name := createIssuer("issuer-unhealthy", "issuer-healthcheck-credentials")

		reconcileOnce(name) // First seen
		reconcileOnce(name) // Validate passes, Check fails

		cond := readyCondition(name)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Message).To(ContainSubstring("healthcheck failed"))
	})
})
