package auth_test

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	infisicalSdk "github.com/infisical/go-sdk"

	"github.com/Infisical/infisical-issuer/api/v1alpha1"
	"github.com/Infisical/infisical-issuer/internal/auth"
	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/model"
)

type fakeStrategy struct {
	callCount int
	result    *model.AuthenticationResult
}

func (f *fakeStrategy) Validate(_ context.Context, _ *v1alpha1.IssuerSpec, _ string) error {
	return nil
}

func (f *fakeStrategy) Authenticate(_ context.Context, _ *model.InfisicalConnection, _ *v1alpha1.IssuerSpec, _ string) (*model.AuthenticationResult, error) {
	f.callCount++
	return f.result, nil
}

var _ = Describe("Resolver registry", func() {
	It("should return an error for an unsupported auth method", func() {
		authCache, err := cache.NewAuthCache()
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(authCache.Cleanup)

		resolver := auth.NewResolver(k8sClient, authCache, logr.Discard())
		spec := newIssuerSpec("unsupported-method")

		err = resolver.Validate(ctx, spec, "default")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unsupported authentication method"))
	})
})

var _ = Describe("Resolver cache behavior", func() {
	var (
		authCache *cache.AuthCache
		fake      *fakeStrategy
		resolver  *auth.Resolver
		spec      *v1alpha1.IssuerSpec
		key       cache.ClientCacheKey
	)

	BeforeEach(func() {
		var err error
		authCache, err = cache.NewAuthCache(cache.WithMinTTLThreshold(1 * time.Second))
		Expect(err).ToNot(HaveOccurred())

		fake = &fakeStrategy{
			result: &model.AuthenticationResult{
				MachineIdentity: infisicalSdk.MachineIdentityCredential{
					AccessToken: "fake-token",
					ExpiresIn:   600,
				},
			},
		}

		resolver = auth.NewResolverForTesting(authCache, map[v1alpha1.AuthMethod]auth.Strategy{
			v1alpha1.AuthMethodUniversal: fake,
		})

		spec = newIssuerSpec(v1alpha1.AuthMethodUniversal)
		key = cache.ClientCacheKey{Name: "issuer-1", Namespace: "default"}
	})

	AfterEach(func() {
		authCache.Cleanup()
	})

	It("should authenticate once and serve the second request from cache", func() {
		r1, err := resolver.Authenticate(ctx, spec, key, "default")
		Expect(err).NotTo(HaveOccurred())
		Expect(r1.AccessToken()).To(Equal("fake-token"))
		Expect(fake.callCount).To(Equal(1))

		r2, err := resolver.Authenticate(ctx, spec, key, "default")
		Expect(err).NotTo(HaveOccurred())
		Expect(r2.AccessToken()).To(Equal("fake-token"))
		Expect(fake.callCount).To(Equal(1))
	})

	It("should re-authenticate after the cache entry is invalidated", func() {
		_, err := resolver.Authenticate(ctx, spec, key, "default")
		Expect(err).NotTo(HaveOccurred())
		Expect(fake.callCount).To(Equal(1))

		resolver.Invalidate(key)

		_, err = resolver.Authenticate(ctx, spec, key, "default")
		Expect(err).NotTo(HaveOccurred())
		Expect(fake.callCount).To(Equal(2))
	})
})
