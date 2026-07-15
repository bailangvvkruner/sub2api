package repository

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type ingressLeaseCacheStub struct {
	acquireCalls int
	refreshCalls int
	releaseCalls int
}

func (c *ingressLeaseCacheStub) AcquireOpenAIWSIngressLease(context.Context, int64, int, string) (bool, error) {
	c.acquireCalls++
	return true, nil
}

func (c *ingressLeaseCacheStub) RefreshOpenAIWSIngressLease(context.Context, int64, string) (bool, error) {
	c.refreshCalls++
	return true, nil
}

func (c *ingressLeaseCacheStub) ReleaseOpenAIWSIngressLease(context.Context, int64, string) error {
	c.releaseCalls++
	return nil
}

func TestLocalConcurrencyCacheWithLeasesKeepsSlotsLocal(t *testing.T) {
	ctx := context.Background()
	leases := &ingressLeaseCacheStub{}
	local := NewLocalConcurrencyCache(1, 60)
	apiKeys, ok := local.(service.APIKeyConcurrencyCache)
	require.True(t, ok)
	cache := newLocalConcurrencyCacheWithLeases(local, apiKeys, leases)

	acquired, err := cache.AcquireAccountSlot(ctx, 101, 1, "request-1")
	require.NoError(t, err)
	require.True(t, acquired)
	require.Zero(t, leases.acquireCalls)
	require.NoError(t, apiKeys.TrackAPIKeySlot(ctx, 202, "request-1"))
	counts, err := apiKeys.GetAPIKeyConcurrencyBatch(ctx, []int64{202})
	require.NoError(t, err)
	require.Equal(t, 1, counts[202])
	require.Zero(t, leases.acquireCalls)

	leaseCache, ok := cache.(service.OpenAIWSIngressLeaseCache)
	require.True(t, ok)
	acquired, err = leaseCache.AcquireOpenAIWSIngressLease(ctx, 202, 1, "lease-1")
	require.NoError(t, err)
	require.True(t, acquired)

	refreshed, err := leaseCache.RefreshOpenAIWSIngressLease(ctx, 202, "lease-1")
	require.NoError(t, err)
	require.True(t, refreshed)
	require.NoError(t, leaseCache.ReleaseOpenAIWSIngressLease(ctx, 202, "lease-1"))
	require.Equal(t, 1, leases.acquireCalls)
	require.Equal(t, 1, leases.refreshCalls)
	require.Equal(t, 1, leases.releaseCalls)
}

func TestProvideConcurrencyCacheLocalRetainsIngressLeaseCapability(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.HotPath.LocalConcurrencySlots = true
	cfg.Gateway.ConcurrencySlotTTLMinutes = 1

	cache := ProvideConcurrencyCache(nil, cfg)
	_, ok := cache.(service.OpenAIWSIngressLeaseCache)
	require.True(t, ok)
	apiKeys, ok := cache.(service.APIKeyConcurrencyCache)
	require.True(t, ok)

	acquired, err := cache.AcquireUserSlot(context.Background(), 303, 1, "request-1")
	require.NoError(t, err)
	require.True(t, acquired, "ordinary request slots must remain process-local")
	require.NoError(t, apiKeys.TrackAPIKeySlot(context.Background(), 404, "request-1"))
	counts, err := apiKeys.GetAPIKeyConcurrencyBatch(context.Background(), []int64{404})
	require.NoError(t, err)
	require.Equal(t, 1, counts[404], "API key request slots must remain process-local")
}
