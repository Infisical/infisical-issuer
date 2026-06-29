package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/model"
	"github.com/Infisical/infisical-issuer/internal/util"
	"github.com/go-logr/logr"
	infisical "github.com/infisical/go-sdk"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Strategy interface {
	Validate(ctx context.Context, spec *v1alpha1.IssuerSpec, resourceNamespace string) error
	Authenticate(ctx context.Context, conn *model.InfisicalConnection, spec *v1alpha1.IssuerSpec, resourceNamespace string) (*model.AuthenticationResult, error)
}

const cacheTTLFraction = 0.7

type Resolver struct {
	client     client.Client
	cache      *cache.AuthCache
	logger     logr.Logger
	strategies map[v1alpha1.AuthMethod]Strategy
}

func NewResolver(c client.Client, authCache *cache.AuthCache, logger logr.Logger) *Resolver {
	r := &Resolver{
		client:     c,
		cache:      authCache,
		logger:     logger.WithName("auth"),
		strategies: map[v1alpha1.AuthMethod]Strategy{},
	}
	r.strategies[v1alpha1.AuthMethodUniversal] = NewUniversalAuth(c)
	r.strategies[v1alpha1.AuthMethodKubernetes] = NewKubernetesAuth(c)
	return r
}

// NewResolverForTesting injects fake strategies; the external test package
// cannot reach the unexported fields otherwise.
func NewResolverForTesting(authCache *cache.AuthCache, strategies map[v1alpha1.AuthMethod]Strategy) *Resolver {
	return &Resolver{
		cache:      authCache,
		logger:     logr.Discard(),
		strategies: strategies,
	}
}

func (r *Resolver) strategy(method v1alpha1.AuthMethod) (Strategy, error) {
	s, ok := r.strategies[method]
	if !ok {
		return nil, fmt.Errorf("%w: %q", model.ErrUnsupportedAuthMethod, method)
	}
	return s, nil
}

func (r *Resolver) Validate(ctx context.Context, spec *v1alpha1.IssuerSpec, resourceNamespace string) error {
	s, err := r.strategy(spec.Authentication.Method)
	if err != nil {
		return err
	}
	return s.Validate(ctx, spec, resourceNamespace)
}

func (r *Resolver) Authenticate(ctx context.Context, spec *v1alpha1.IssuerSpec, key cache.ClientCacheKey, resourceNamespace string) (*model.AuthenticationResult, error) {
	s, err := r.strategy(spec.Authentication.Method)
	if err != nil {
		return nil, err
	}

	if cached, found := r.cache.Get(key); found {
		r.logger.V(1).Info("reusing cached authentication", "issuer", key.String())
		return cached, nil
	}

	conn, err := r.Connection(ctx, spec, resourceNamespace)
	if err != nil {
		return nil, err
	}

	result, err := s.Authenticate(ctx, conn, spec, resourceNamespace)
	if err != nil {
		return nil, err
	}

	// Cache for 70% of the token lifetime. A non-positive lifetime is not cached,
	// so we re-authenticate next time rather than cache it forever.
	if expiresIn := result.MachineIdentity.ExpiresIn; expiresIn <= 0 {
		r.logger.V(1).Info("authenticated with Infisical; token reported no positive lifetime, not caching", "issuer", key.String(), "method", spec.Authentication.Method)
	} else {
		ttl := time.Duration(float64(expiresIn)*cacheTTLFraction) * time.Second
		if r.cache.Set(key, result, ttl) {
			r.logger.V(1).Info("authenticated with Infisical, cached credentials", "issuer", key.String(), "method", spec.Authentication.Method, "ttl", ttl)
		} else {
			r.logger.V(1).Info("authenticated with Infisical; token lifetime below cache threshold, not caching", "issuer", key.String(), "method", spec.Authentication.Method, "ttl", ttl)
		}
	}

	return result, nil
}

func (r *Resolver) Invalidate(key cache.ClientCacheKey) {
	r.cache.Delete(key)
}

func (r *Resolver) Connection(ctx context.Context, spec *v1alpha1.IssuerSpec, resourceNamespace string) (*model.InfisicalConnection, error) {
	conn := &model.InfisicalConnection{Host: spec.URL}
	if spec.TLS != nil {
		caCert, err := util.ResolveSecretReference(ctx, r.client, spec.TLS.CACertificate, resourceNamespace, ".spec.tls.caCertificate")
		if err != nil {
			return nil, err
		}
		conn.CaCertificate = caCert
	}
	return conn, nil
}

func newSDKClient(ctx context.Context, conn *model.InfisicalConnection) infisical.InfisicalClientInterface {
	return infisical.NewInfisicalClient(ctx, infisical.Config{
		SiteUrl:          conn.Host,
		CaCertificate:    conn.CaCertificate,
		AutoTokenRefresh: infisical.BoolPtr(false),
	})
}
