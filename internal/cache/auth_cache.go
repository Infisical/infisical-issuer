package cache

import (
	"fmt"
	"time"

	"github.com/Infisical/infisical-issuer/internal/model"
	"github.com/dgraph-io/ristretto/v2"
)

type ClientCacheKey struct {
	Name      string
	Namespace string
	// Generation is the issuer's metadata.generation, so an in-place spec edit
	// yields a new key and never reuses a stale token.
	Generation int64
}

func (k ClientCacheKey) String() string {
	return fmt.Sprintf("%s/%s/%d", k.Namespace, k.Name, k.Generation)
}

type AuthCache struct {
	cache           *ristretto.Cache[string, *model.AuthenticationResult]
	minTTLThreshold time.Duration
}

type AuthCacheOption func(*AuthCache)

func WithMinTTLThreshold(minTTL time.Duration) AuthCacheOption {
	return func(ac *AuthCache) {
		ac.minTTLThreshold = minTTL
	}
}

func NewAuthCache(opts ...AuthCacheOption) (*AuthCache, error) {
	c, err := ristretto.NewCache(&ristretto.Config[string, *model.AuthenticationResult]{
		NumCounters:        1000,
		MaxCost:            1 << 30,
		BufferItems:        64,
		IgnoreInternalCost: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create auth cache: %w", err)
	}
	ac := &AuthCache{cache: c}
	for _, opt := range opts {
		opt(ac)
	}
	return ac, nil
}

func (c *AuthCache) Get(key ClientCacheKey) (*model.AuthenticationResult, bool) {
	return c.cache.Get(key.String())
}

// Set caches the result and reports whether it was stored. A non-positive TTL is
// rejected (ristretto treats ttl==0 as no-expiry), as is a TTL below minTTLThreshold.
func (c *AuthCache) Set(key ClientCacheKey, value *model.AuthenticationResult, ttl time.Duration) bool {
	if ttl <= 0 || ttl < c.minTTLThreshold {
		return false
	}
	c.cache.SetWithTTL(key.String(), value, 1, ttl)
	c.cache.Wait()
	return true
}

func (c *AuthCache) Delete(key ClientCacheKey) {
	c.cache.Del(key.String())
}

func (c *AuthCache) Cleanup() {
	if c.cache != nil {
		c.cache.Close()
	}
}
