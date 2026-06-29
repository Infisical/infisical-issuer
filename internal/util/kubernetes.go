package util

import (
	"context"
	"fmt"
	"strings"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const serviceAccountTokenTTLSeconds int64 = 600

// confineNamespace rejects a reference that names a namespace other than
// resourceNamespace, so an issuer cannot read Secrets or mint tokens elsewhere.
func confineNamespace(refNamespace, resourceNamespace, fieldPath string) error {
	if refNamespace != "" && refNamespace != resourceNamespace {
		return fmt.Errorf("%s references namespace %q but must resolve within %q; cross-namespace references are not allowed", fieldPath, refNamespace, resourceNamespace)
	}
	return nil
}

func ResolveSecretReference(ctx context.Context, c client.Client, ref v1alpha1.SecretReference, resourceNamespace, fieldPath string) (string, error) {
	if err := confineNamespace(ref.Namespace, resourceNamespace, fieldPath); err != nil {
		return "", err
	}

	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: resourceNamespace}, secret); err != nil {
		return "", fmt.Errorf("unable to fetch secret for %s (secret %s/%s): %w", fieldPath, resourceNamespace, ref.Name, err)
	}

	val, ok := secret.Data[ref.Key]
	if !ok || len(val) == 0 {
		return "", fmt.Errorf("secret %s/%s has no value for key %q (referenced by %s)", resourceNamespace, ref.Name, ref.Key, fieldPath)
	}

	return strings.TrimSpace(string(val)), nil
}

func MintServiceAccountToken(ctx context.Context, c client.Client, ref v1alpha1.NamespacedName, resourceNamespace string, audiences []string) (string, error) {
	if err := confineNamespace(ref.Namespace, resourceNamespace, ".spec.authentication.kubernetes.serviceAccountRef"); err != nil {
		return "", err
	}

	// Construct the ServiceAccount inline rather than fetching it: the TokenRequest
	// is a direct write needing only serviceaccounts/token create, avoiding a
	// cluster-wide ServiceAccount watch.
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: resourceNamespace},
	}

	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: ptr.To(serviceAccountTokenTTLSeconds),
		},
	}
	if len(audiences) > 0 {
		tokenRequest.Spec.Audiences = audiences
	}

	if err := c.SubResource("token").Create(ctx, sa, tokenRequest); err != nil {
		return "", fmt.Errorf("unable to create token for service account %s/%s: %w", resourceNamespace, ref.Name, err)
	}

	if tokenRequest.Status.Token == "" {
		return "", fmt.Errorf("token request for service account %s/%s returned an empty token", resourceNamespace, ref.Name)
	}

	return tokenRequest.Status.Token, nil
}
