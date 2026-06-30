package repository

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
	cache := newLocalBillingCache(next, 1024)
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
	cache := newLocalBillingCache(next, 1024)
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
	require.Equal(t, int64(1), next.quotaIncrs.Load())

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
