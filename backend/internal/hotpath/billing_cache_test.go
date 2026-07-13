package hotpath

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type localBillingNextStub struct {
	balanceGets atomic.Int64
	quotaIncrs  atomic.Int64
}

func (s *localBillingNextStub) GetUserBalance(context.Context, int64) (float64, error) {
	s.balanceGets.Add(1)
	return 42, nil
}

func (s *localBillingNextStub) SetUserBalance(context.Context, int64, float64) error    { return nil }
func (s *localBillingNextStub) DeductUserBalance(context.Context, int64, float64) error { return nil }
func (s *localBillingNextStub) InvalidateUserBalance(context.Context, int64) error      { return nil }
func (s *localBillingNextStub) GetSubscriptionCache(context.Context, int64, int64) (*service.SubscriptionCacheData, error) {
	return nil, errors.New("miss")
}
func (s *localBillingNextStub) SetSubscriptionCache(context.Context, int64, int64, *service.SubscriptionCacheData) error {
	return nil
}
func (s *localBillingNextStub) UpdateSubscriptionUsage(context.Context, int64, int64, float64) error {
	return nil
}
func (s *localBillingNextStub) InvalidateSubscriptionCache(context.Context, int64, int64) error {
	return nil
}
func (s *localBillingNextStub) GetAPIKeyRateLimit(context.Context, int64) (*service.APIKeyRateLimitCacheData, error) {
	return nil, errors.New("miss")
}
func (s *localBillingNextStub) SetAPIKeyRateLimit(context.Context, int64, *service.APIKeyRateLimitCacheData) error {
	return nil
}
func (s *localBillingNextStub) UpdateAPIKeyRateLimitUsage(context.Context, int64, float64) error {
	return nil
}
func (s *localBillingNextStub) InvalidateAPIKeyRateLimit(context.Context, int64) error { return nil }
func (s *localBillingNextStub) GetUserPlatformQuotaCache(context.Context, int64, string) (*service.UserPlatformQuotaCacheEntry, bool, error) {
	return nil, false, nil
}
func (s *localBillingNextStub) SetUserPlatformQuotaCache(context.Context, int64, string, *service.UserPlatformQuotaCacheEntry, time.Duration) error {
	return nil
}
func (s *localBillingNextStub) DeleteUserPlatformQuotaCache(context.Context, int64, string) error {
	return nil
}
func (s *localBillingNextStub) IncrUserPlatformQuotaUsageCache(context.Context, int64, string, float64, time.Duration, bool) error {
	s.quotaIncrs.Add(1)
	return nil
}
func (s *localBillingNextStub) PopDirtyUserPlatformQuotaKeys(context.Context, int) ([]service.UserPlatformQuotaKey, error) {
	return nil, nil
}
func (s *localBillingNextStub) ReaddDirtyUserPlatformQuotaKeys(context.Context, []service.UserPlatformQuotaKey) error {
	return nil
}
func (s *localBillingNextStub) BatchGetUserPlatformQuotaCache(context.Context, []service.UserPlatformQuotaKey) ([]*service.UserPlatformQuotaCacheEntry, error) {
	return nil, nil
}

func TestLocalBillingCache_BalanceReadsHitLocalBeforeRedis(t *testing.T) {
	next := &localBillingNextStub{}
	cache := NewLocalBillingCache(next, 1024)
	ctx := context.Background()

	got, err := cache.GetUserBalance(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, 42.0, got)

	got, err = cache.GetUserBalance(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, 42.0, got)
	require.Equal(t, int64(1), next.balanceGets.Load())

	require.NoError(t, cache.DeductUserBalance(ctx, 1, 2))
	got, err = cache.GetUserBalance(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, 40.0, got)
	require.Equal(t, int64(1), next.balanceGets.Load())
}

func TestLocalBillingCache_UserPlatformQuotaDirtyServesFlusherFromLocal(t *testing.T) {
	next := &localBillingNextStub{}
	cache := NewLocalBillingCache(next, 1024)
	ctx := context.Background()
	limit := 10.0
	now := time.Now().UTC()
	entry := &service.UserPlatformQuotaCacheEntry{
		SchemaVersion:      service.UserPlatformQuotaCacheSchemaV1,
		DailyLimitUSD:      &limit,
		DailyUsageUSD:      1,
		WeeklyUsageUSD:     2,
		MonthlyUsageUSD:    3,
		DailyWindowStart:   &now,
		WeeklyWindowStart:  &now,
		MonthlyWindowStart: &now,
	}

	require.NoError(t, cache.SetUserPlatformQuotaCache(ctx, 7, "openai", entry, time.Hour))
	require.NoError(t, cache.IncrUserPlatformQuotaUsageCache(ctx, 7, "openai", 2.5, time.Hour, true))
	require.Equal(t, int64(0), next.quotaIncrs.Load())

	keys, err := cache.PopDirtyUserPlatformQuotaKeys(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, []service.UserPlatformQuotaKey{{UserID: 7, Platform: "openai"}}, keys)

	got, err := cache.BatchGetUserPlatformQuotaCache(ctx, keys)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.NotNil(t, got[0])
	require.Equal(t, 3.5, got[0].DailyUsageUSD)
	require.Equal(t, 4.5, got[0].WeeklyUsageUSD)
	require.Equal(t, 5.5, got[0].MonthlyUsageUSD)
}

func TestLocalBillingCache_UserPlatformQuotaWriteThroughPassesToNext(t *testing.T) {
	next := &localBillingNextStub{}
	cache := NewLocalBillingCacheWithOptions(next, 1024, true)
	ctx := context.Background()
	limit := 10.0
	now := time.Now().UTC()
	entry := &service.UserPlatformQuotaCacheEntry{
		SchemaVersion:      service.UserPlatformQuotaCacheSchemaV1,
		DailyLimitUSD:      &limit,
		DailyWindowStart:   &now,
		WeeklyWindowStart:  &now,
		MonthlyWindowStart: &now,
	}

	require.NoError(t, cache.SetUserPlatformQuotaCache(ctx, 7, "openai", entry, time.Hour))
	require.NoError(t, cache.IncrUserPlatformQuotaUsageCache(ctx, 7, "openai", 2.5, time.Hour, true))
	require.Equal(t, int64(1), next.quotaIncrs.Load())
}

func TestLocalBillingCache_UserPlatformQuotaDirtySurvivesExpiration(t *testing.T) {
	cache := NewLocalBillingCache(nil, 1024).(*localBillingCache)
	ctx := context.Background()
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	cache.clock = func() time.Time { return now }
	entry := localQuotaTestEntry(now, 1)

	require.NoError(t, cache.SetUserPlatformQuotaCache(ctx, 7, "openai", entry, time.Second))
	require.NoError(t, cache.IncrUserPlatformQuotaUsageCache(ctx, 7, "openai", 2.5, time.Second, true))
	now = now.Add(2 * time.Second)

	got, ok, err := cache.GetUserPlatformQuotaCache(ctx, 7, "openai")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 3.5, got.DailyUsageUSD)

	keys, err := cache.PopDirtyUserPlatformQuotaKeys(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, []service.UserPlatformQuotaKey{{UserID: 7, Platform: "openai"}}, keys)
	now = now.Add(24 * time.Hour)

	entries, err := cache.BatchGetUserPlatformQuotaCache(ctx, keys)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.NotNil(t, entries[0])
	require.Equal(t, 3.5, entries[0].DailyUsageUSD)

	cache.AcknowledgeUserPlatformQuotaFlush(keys)
	_, ok, err = cache.GetUserPlatformQuotaCache(ctx, 7, "openai")
	require.NoError(t, err)
	require.False(t, ok, "expired clean entry should become evictable after flush ACK")
}

func TestLocalBillingCache_UserPlatformQuotaCapacityPreservesDirty(t *testing.T) {
	cache := NewLocalBillingCache(nil, 1024).(*localBillingCache)
	cache.maxEntries = 2
	ctx := context.Background()
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	cache.clock = func() time.Time { return now }
	dirtyKey := localQuotaKey{userID: 1, platform: "openai"}
	cleanOldKey := localQuotaKey{userID: 2, platform: "openai"}
	cleanNewKey := localQuotaKey{userID: 3, platform: "openai"}

	require.NoError(t, cache.SetUserPlatformQuotaCache(ctx, dirtyKey.userID, dirtyKey.platform, localQuotaTestEntry(now, 1), time.Hour))
	require.NoError(t, cache.IncrUserPlatformQuotaUsageCache(ctx, dirtyKey.userID, dirtyKey.platform, 1, time.Hour, true))
	require.NoError(t, cache.SetUserPlatformQuotaCache(ctx, cleanOldKey.userID, cleanOldKey.platform, localQuotaTestEntry(now, 2), time.Hour))
	require.NoError(t, cache.SetUserPlatformQuotaCache(ctx, cleanNewKey.userID, cleanNewKey.platform, localQuotaTestEntry(now, 3), time.Hour))

	cache.quotaMu.Lock()
	_, dirtyPresent := cache.quotas[dirtyKey]
	_, cleanOldPresent := cache.quotas[cleanOldKey]
	_, cleanNewPresent := cache.quotas[cleanNewKey]
	cache.quotaMu.Unlock()
	require.True(t, dirtyPresent, "dirty entry must not be selected as the LRU victim")
	require.False(t, cleanOldPresent, "the least recently used clean entry should be evicted")
	require.True(t, cleanNewPresent)
}

func TestLocalBillingCache_UserPlatformQuotaCapacityAllowsDirtyOverflow(t *testing.T) {
	cache := NewLocalBillingCache(nil, 1024).(*localBillingCache)
	cache.maxEntries = 2
	ctx := context.Background()
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	cache.clock = func() time.Time { return now }
	keys := []service.UserPlatformQuotaKey{
		{UserID: 1, Platform: "openai"},
		{UserID: 2, Platform: "openai"},
		{UserID: 3, Platform: "openai"},
	}

	for _, key := range keys[:2] {
		require.NoError(t, cache.SetUserPlatformQuotaCache(ctx, key.UserID, key.Platform, localQuotaTestEntry(now, float64(key.UserID)), time.Hour))
		require.NoError(t, cache.IncrUserPlatformQuotaUsageCache(ctx, key.UserID, key.Platform, 1, time.Hour, true))
	}
	// A failed flush can re-add a key before its snapshot is locally reloaded.
	// Once reloaded, all three entries are dirty and must survive capacity enforcement.
	require.NoError(t, cache.ReaddDirtyUserPlatformQuotaKeys(ctx, keys[2:]))
	require.NoError(t, cache.SetUserPlatformQuotaCache(ctx, keys[2].UserID, keys[2].Platform, localQuotaTestEntry(now, 3), time.Hour))

	cache.quotaMu.Lock()
	quotaCount := len(cache.quotas)
	dirtyCount := len(cache.quotaDirty)
	cache.quotaMu.Unlock()
	require.Equal(t, 3, quotaCount, "all-dirty cache should temporarily exceed capacity")
	require.Equal(t, 3, dirtyCount)

	popped, err := cache.PopDirtyUserPlatformQuotaKeys(ctx, 10)
	require.NoError(t, err)
	require.ElementsMatch(t, keys, popped)
	entries, err := cache.BatchGetUserPlatformQuotaCache(ctx, popped)
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for _, entry := range entries {
		require.NotNil(t, entry)
	}
}

func localQuotaTestEntry(now time.Time, usage float64) *service.UserPlatformQuotaCacheEntry {
	return &service.UserPlatformQuotaCacheEntry{
		SchemaVersion:      service.UserPlatformQuotaCacheSchemaV1,
		DailyUsageUSD:      usage,
		WeeklyUsageUSD:     usage,
		MonthlyUsageUSD:    usage,
		DailyWindowStart:   &now,
		WeeklyWindowStart:  &now,
		MonthlyWindowStart: &now,
	}
}
