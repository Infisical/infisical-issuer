package cache_test

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	infisicalSdk "github.com/infisical/go-sdk"

	"github.com/Infisical/infisical-issuer/internal/cache"
	"github.com/Infisical/infisical-issuer/internal/model"
)

func TestCache(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cache Suite")
}

func newAuthResult(token string) *model.AuthenticationResult {
	return &model.AuthenticationResult{
		MachineIdentity: infisicalSdk.MachineIdentityCredential{AccessToken: token},
	}
}

var _ = Describe("AuthCache", func() {
	var (
		authCache *cache.AuthCache
		key       cache.ClientCacheKey
	)

	BeforeEach(func() {
		key = cache.ClientCacheKey{Name: "test-issuer", Namespace: "default"}
	})

	AfterEach(func() {
		if authCache != nil {
			authCache.Cleanup()
		}
	})

	Describe("happy path", func() {
		BeforeEach(func() {
			var err error
			authCache, err = cache.NewAuthCache()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should store and retrieve a value", func() {
			authCache.Set(key, newAuthResult("token-1"), 30*time.Second)

			result, found := authCache.Get(key)
			Expect(found).To(BeTrue())
			Expect(result.AccessToken()).To(Equal("token-1"))
		})

		It("should return false for a key that was never set", func() {
			_, found := authCache.Get(key)
			Expect(found).To(BeFalse())
		})

		It("should not cache a value with a non-positive TTL", func() {
			Expect(authCache.Set(key, newAuthResult("zero-ttl"), 0)).To(BeFalse())
			_, found := authCache.Get(key)
			Expect(found).To(BeFalse())

			Expect(authCache.Set(key, newAuthResult("negative-ttl"), -5*time.Second)).To(BeFalse())
			_, found = authCache.Get(key)
			Expect(found).To(BeFalse())
		})

		It("should treat keys that differ only by generation as distinct", func() {
			gen1 := cache.ClientCacheKey{Name: "iss", Namespace: "default", Generation: 1}
			gen2 := cache.ClientCacheKey{Name: "iss", Namespace: "default", Generation: 2}

			Expect(authCache.Set(gen1, newAuthResult("old"), 30*time.Second)).To(BeTrue())

			_, found := authCache.Get(gen2)
			Expect(found).To(BeFalse(), "a new generation must not hit the prior generation's token")

			result, found := authCache.Get(gen1)
			Expect(found).To(BeTrue())
			Expect(result.AccessToken()).To(Equal("old"))
		})

		It("should delete a cached entry", func() {
			authCache.Set(key, newAuthResult("token-1"), 30*time.Second)

			authCache.Delete(key)

			_, found := authCache.Get(key)
			Expect(found).To(BeFalse())
		})
	})

	Describe("TTL expiration", func() {
		BeforeEach(func() {
			var err error
			authCache, err = cache.NewAuthCache()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should not find a key after its TTL expires", func() {
			authCache.Set(key, newAuthResult("short-lived"), 2*time.Second)

			result, found := authCache.Get(key)
			Expect(found).To(BeTrue())
			Expect(result.AccessToken()).To(Equal("short-lived"))

			time.Sleep(3 * time.Second)

			_, found = authCache.Get(key)
			Expect(found).To(BeFalse())
		})
	})

	Describe("minTTLThreshold", func() {
		BeforeEach(func() {
			var err error
			authCache, err = cache.NewAuthCache(cache.WithMinTTLThreshold(5 * time.Second))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should not cache a value when the TTL is below the threshold", func() {
			authCache.Set(key, newAuthResult("below-threshold"), 2*time.Second)

			_, found := authCache.Get(key)
			Expect(found).To(BeFalse())
		})

		It("should cache a value when the TTL meets the threshold", func() {
			authCache.Set(key, newAuthResult("above-threshold"), 10*time.Second)

			result, found := authCache.Get(key)
			Expect(found).To(BeTrue())
			Expect(result.AccessToken()).To(Equal("above-threshold"))
		})
	})
})
