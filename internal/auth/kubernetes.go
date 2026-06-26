package auth

import (
	"context"
	"fmt"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/model"
	"github.com/Infisical/infisical-issuer/internal/util"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type kubernetesAuth struct {
	client client.Client
}

func NewKubernetesAuth(c client.Client) Strategy {
	return &kubernetesAuth{client: c}
}

func (k *kubernetesAuth) Validate(ctx context.Context, spec *v1alpha1.IssuerSpec, resourceNamespace string) error {
	cfg := spec.Authentication.Kubernetes
	if cfg == nil {
		return fmt.Errorf("%w: method is %q but .spec.authentication.kubernetes is not set", model.ErrInvalidIssuerSpec, v1alpha1.AuthMethodKubernetes)
	}
	if cfg.ServiceAccountRef.Name == "" {
		return fmt.Errorf("%w: .spec.authentication.kubernetes.serviceAccountRef requires a name", model.ErrInvalidIssuerSpec)
	}
	if _, err := util.ResolveSecretReference(ctx, k.client, cfg.IdentityIDRef, resourceNamespace, ".spec.authentication.kubernetes.identityIdRef"); err != nil {
		return err
	}
	return nil
}

func (k *kubernetesAuth) Authenticate(ctx context.Context, conn *model.InfisicalConnection, spec *v1alpha1.IssuerSpec, resourceNamespace string) (*model.AuthenticationResult, error) {
	cfg := spec.Authentication.Kubernetes
	if cfg == nil {
		return nil, fmt.Errorf("%w: .spec.authentication.kubernetes is nil", model.ErrInvalidIssuerSpec)
	}

	identityID, err := util.ResolveSecretReference(ctx, k.client, cfg.IdentityIDRef, resourceNamespace, ".spec.authentication.kubernetes.identityIdRef")
	if err != nil {
		return nil, err
	}

	token, err := util.MintServiceAccountToken(ctx, k.client, cfg.ServiceAccountRef, resourceNamespace, cfg.ServiceAccountTokenAudiences)
	if err != nil {
		return nil, err
	}

	cred, err := newSDKClient(ctx, conn).Auth().KubernetesRawServiceAccountTokenLogin(identityID, token)
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate with Kubernetes Auth: %w", err)
	}

	return &model.AuthenticationResult{MachineIdentity: cred}, nil
}
