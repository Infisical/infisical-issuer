package util_test

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/util"
)

func newClientWithSecret(namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: namespace},
		Data:       map[string][]byte{"value": []byte("secret-data")},
	}
}

func TestResolveSecretReferenceConfinement(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(newClientWithSecret("team-a")).Build()
	ctx := context.Background()

	t.Run("resolves a reference within the resource namespace", func(t *testing.T) {
		ref := v1alpha1.SecretReference{Name: "creds", Namespace: "team-a", Key: "value"}
		val, err := util.ResolveSecretReference(ctx, c, ref, "team-a", "field")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "secret-data" {
			t.Fatalf("got %q, want %q", val, "secret-data")
		}
	})

	t.Run("defaults to the resource namespace when the reference omits it", func(t *testing.T) {
		ref := v1alpha1.SecretReference{Name: "creds", Key: "value"}
		val, err := util.ResolveSecretReference(ctx, c, ref, "team-a", "field")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "secret-data" {
			t.Fatalf("got %q, want %q", val, "secret-data")
		}
	})

	t.Run("rejects a reference to a foreign namespace", func(t *testing.T) {
		// A namespaced Issuer in team-a must not be able to read team-b's Secret.
		ref := v1alpha1.SecretReference{Name: "creds", Namespace: "team-b", Key: "value"}
		_, err := util.ResolveSecretReference(ctx, c, ref, "team-a", "field")
		if err == nil {
			t.Fatal("expected a cross-namespace reference to be rejected, got nil")
		}
		if got := err.Error(); !strings.Contains(got, "cross-namespace references are not allowed") {
			t.Fatalf("error %q does not mention the cross-namespace rejection", got)
		}
	})
}
