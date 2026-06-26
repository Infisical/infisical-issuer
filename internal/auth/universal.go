package auth

import (
	"context"
	"fmt"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/model"
	"github.com/Infisical/infisical-issuer/internal/util"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type universalAuth struct {
	client client.Client
}

func NewUniversalAuth(c client.Client) Strategy {
	return &universalAuth{client: c}
}

func (u *universalAuth) Validate(ctx context.Context, spec *v1alpha1.IssuerSpec, resourceNamespace string) error {
	cfg := spec.Authentication.Universal
	if cfg == nil {
		return fmt.Errorf("%w: method is %q but .spec.authentication.universal is not set", model.ErrInvalidIssuerSpec, v1alpha1.AuthMethodUniversal)
	}
	if _, err := util.ResolveSecretReference(ctx, u.client, cfg.ClientIDRef, resourceNamespace, ".spec.authentication.universal.clientIdRef"); err != nil {
		return err
	}
	if _, err := util.ResolveSecretReference(ctx, u.client, cfg.ClientSecretRef, resourceNamespace, ".spec.authentication.universal.clientSecretRef"); err != nil {
		return err
	}
	return nil
}

func (u *universalAuth) Authenticate(ctx context.Context, conn *model.InfisicalConnection, spec *v1alpha1.IssuerSpec, resourceNamespace string) (*model.AuthenticationResult, error) {
	cfg := spec.Authentication.Universal
	if cfg == nil {
		return nil, fmt.Errorf("%w: .spec.authentication.universal is nil", model.ErrInvalidIssuerSpec)
	}

	clientID, err := util.ResolveSecretReference(ctx, u.client, cfg.ClientIDRef, resourceNamespace, ".spec.authentication.universal.clientIdRef")
	if err != nil {
		return nil, err
	}
	clientSecret, err := util.ResolveSecretReference(ctx, u.client, cfg.ClientSecretRef, resourceNamespace, ".spec.authentication.universal.clientSecretRef")
	if err != nil {
		return nil, err
	}

	cred, err := newSDKClient(ctx, conn).Auth().UniversalAuthLogin(clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate with Universal Auth: %w", err)
	}

	return &model.AuthenticationResult{MachineIdentity: cred}, nil
}
