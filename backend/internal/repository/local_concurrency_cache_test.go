package repository

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestLocalConcurrencyCacheAccountSlots(t *testing.T) {
	ctx := context.Background()
	cache := NewLocalConcurrencyCache(1, 60)

	ok, err := cache.AcquireAccountSlot(ctx, 1001, 2, "req-1")
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = cache.AcquireAccountSlot(ctx, 1001, 2, "req-2")
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = cache.AcquireAccountSlot(ctx, 1001, 2, "req-3")
	require.NoError(t, err)
	require.False(t, ok)

	current, err := cache.GetAccountConcurrency(ctx, 1001)
	require.NoError(t, err)
	require.Equal(t, 2, current)

	require.NoError(t, cache.ReleaseAccountSlot(ctx, 1001, "req-1"))

	current, err = cache.GetAccountConcurrency(ctx, 1001)
	require.NoError(t, err)
	require.Equal(t, 1, current)
}

func TestLocalConcurrencyCacheDuplicateRequestID(t *testing.T) {
	ctx := context.Background()
	cache := NewLocalConcurrencyCache(1, 60)

	ok, err := cache.AcquireUserSlot(ctx, 2001, 1, "same-req")
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = cache.AcquireUserSlot(ctx, 2001, 1, "same-req")
	require.NoError(t, err)
	require.True(t, ok)

	current, err := cache.GetUserConcurrency(ctx, 2001)
	require.NoError(t, err)
	require.Equal(t, 1, current)
}

func TestLocalConcurrencyCacheLoadBatchIncludesWaitCounts(t *testing.T) {
	ctx := context.Background()
	cache := NewLocalConcurrencyCache(1, 60)

	ok, err := cache.AcquireAccountSlot(ctx, 3001, 3, "req-1")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = cache.AcquireAccountSlot(ctx, 3001, 3, "req-2")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = cache.IncrementAccountWaitCount(ctx, 3001, 10)
	require.NoError(t, err)
	require.True(t, ok)

	loads, err := cache.GetAccountsLoadBatch(ctx, []service.AccountWithConcurrency{
		{ID: 3001, MaxConcurrency: 3},
		{ID: 3002, MaxConcurrency: 2},
	})
	require.NoError(t, err)

	require.Equal(t, 2, loads[3001].CurrentConcurrency)
	require.Equal(t, 1, loads[3001].WaitingCount)
	require.Equal(t, 100, loads[3001].LoadRate)
	require.Equal(t, 0, loads[3002].CurrentConcurrency)
	require.Equal(t, 0, loads[3002].WaitingCount)
	require.Equal(t, 0, loads[3002].LoadRate)
}

func TestLocalConcurrencyCacheWaitCountLimitAndDecrement(t *testing.T) {
	ctx := context.Background()
	cache := NewLocalConcurrencyCache(1, 60)

	ok, err := cache.IncrementWaitCount(ctx, 4001, 1)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = cache.IncrementWaitCount(ctx, 4001, 1)
	require.NoError(t, err)
	require.False(t, ok)

	require.NoError(t, cache.DecrementWaitCount(ctx, 4001))

	loads, err := cache.GetUsersLoadBatch(ctx, []service.UserWithConcurrency{{ID: 4001, MaxConcurrency: 1}})
	require.NoError(t, err)
	require.Equal(t, 0, loads[4001].WaitingCount)
	require.Equal(t, 0, loads[4001].LoadRate)
}
