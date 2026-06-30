package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type usageBillingWriteBehindUserRepoStub struct {
	UserRepository

	calls      int
	lastUserID int64
	lastAmount float64
	err        error
}

func (s *usageBillingWriteBehindUserRepoStub) DeductBalance(ctx context.Context, id int64, amount float64) error {
	s.calls++
	s.lastUserID = id
	s.lastAmount = amount
	return s.err
}

type usageBillingWriteBehindSubRepoStub struct {
	UserSubscriptionRepository

	calls  int
	lastID int64
	amount float64
	err    error
}

func (s *usageBillingWriteBehindSubRepoStub) IncrementUsage(ctx context.Context, id int64, costUSD float64) error {
	s.calls++
	s.lastID = id
	s.amount = costUSD
	return s.err
}

type usageBillingWriteBehindAccountRepoStub struct {
	AccountRepository

	calls  int
	lastID int64
	amount float64
	err    error
}

func (s *usageBillingWriteBehindAccountRepoStub) IncrementQuotaUsed(ctx context.Context, id int64, amount float64) error {
	s.calls++
	s.lastID = id
	s.amount = amount
	return s.err
}

type usageBillingWriteBehindAPIKeyUpdaterStub struct {
	quotaCalls     int
	rateCalls      int
	lastQuotaKeyID int64
	lastRateKeyID  int64
	quotaAmount    float64
	rateAmount     float64
	err            error
}

func (s *usageBillingWriteBehindAPIKeyUpdaterStub) UpdateQuotaUsed(ctx context.Context, apiKeyID int64, cost float64) error {
	s.quotaCalls++
	s.lastQuotaKeyID = apiKeyID
	s.quotaAmount = cost
	return s.err
}

func (s *usageBillingWriteBehindAPIKeyUpdaterStub) UpdateRateLimitUsage(ctx context.Context, apiKeyID int64, cost float64) error {
	s.rateCalls++
	s.lastRateKeyID = apiKeyID
	s.rateAmount = cost
	return s.err
}

func newUsageBillingWriteBehindForTest() *UsageBillingWriteBehind {
	cfg := &config.Config{}
	cfg.Gateway.HotPath.UsageBillingWriteBehind = true
	cfg.Gateway.HotPath.UsageBillingFlushIntervalMs = 30000
	cfg.Idempotency.DefaultTTLSeconds = 60
	cfg.APIKeyAuth.L2TTLSeconds = 60
	return NewUsageBillingWriteBehind(cfg)
}

func TestUsageBillingWriteBehind_AggregatesAndFlushesOnce(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	userRepo := &usageBillingWriteBehindUserRepoStub{}
	subRepo := &usageBillingWriteBehindSubRepoStub{}
	accountRepo := &usageBillingWriteBehindAccountRepoStub{}
	apiKeyUpdater := &usageBillingWriteBehindAPIKeyUpdaterStub{}
	subID := int64(88)
	deps := &billingDeps{
		userRepo:    userRepo,
		userSubRepo: subRepo,
		accountRepo: accountRepo,
	}

	for _, cmd := range []*UsageBillingCommand{
		{
			RequestID:           "req-balance-1",
			APIKeyID:            7,
			UserID:              42,
			AccountID:           99,
			BalanceCost:         1.25,
			APIKeyQuotaCost:     1.25,
			APIKeyRateLimitCost: 1.25,
			AccountQuotaCost:    0.50,
		},
		{
			RequestID:           "req-balance-2",
			APIKeyID:            7,
			UserID:              42,
			AccountID:           99,
			BalanceCost:         2.75,
			APIKeyQuotaCost:     2.75,
			APIKeyRateLimitCost: 2.75,
			AccountQuotaCost:    0.75,
		},
		{
			RequestID:        "req-sub-1",
			APIKeyID:         7,
			UserID:           42,
			AccountID:        99,
			SubscriptionID:   &subID,
			SubscriptionCost: 3.50,
		},
	} {
		result, handled, err := wb.Apply(context.Background(), cmd, &postUsageBillingParams{
			User:          &User{ID: 42, Balance: 10},
			APIKey:        &APIKey{ID: 7, Quota: 100},
			Account:       &Account{ID: 99, Type: AccountTypeAPIKey},
			APIKeyService: apiKeyUpdater,
		}, deps)
		require.NoError(t, err)
		require.True(t, handled)
		require.True(t, result.Applied)
	}

	stats := wb.Stats()
	require.Equal(t, 1, stats.PendingBalanceKeys)
	require.Equal(t, 1, stats.PendingSubscriptionKeys)
	require.Equal(t, 1, stats.PendingAPIKeyQuotaKeys)
	require.Equal(t, 1, stats.PendingAPIKeyRateKeys)
	require.Equal(t, 1, stats.PendingAccountQuotaKeys)
	require.Equal(t, uint64(3), stats.AppliedTotal)
	require.Equal(t, 0, userRepo.calls)

	wb.Flush(context.Background(), deps)

	require.Equal(t, 1, userRepo.calls)
	require.Equal(t, int64(42), userRepo.lastUserID)
	require.InDelta(t, 4.0, userRepo.lastAmount, 1e-12)
	require.Equal(t, 1, subRepo.calls)
	require.Equal(t, subID, subRepo.lastID)
	require.InDelta(t, 3.5, subRepo.amount, 1e-12)
	require.Equal(t, 1, apiKeyUpdater.quotaCalls)
	require.InDelta(t, 4.0, apiKeyUpdater.quotaAmount, 1e-12)
	require.Equal(t, 1, apiKeyUpdater.rateCalls)
	require.InDelta(t, 4.0, apiKeyUpdater.rateAmount, 1e-12)
	require.Equal(t, 1, accountRepo.calls)
	require.InDelta(t, 1.25, accountRepo.amount, 1e-12)
	require.Equal(t, 0, wb.Stats().PendingBalanceKeys)
}

func TestUsageBillingWriteBehind_DeduplicatesRequestID(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	deps := &billingDeps{userRepo: &usageBillingWriteBehindUserRepoStub{}}
	cmd := &UsageBillingCommand{
		RequestID:   "same-request",
		APIKeyID:    7,
		UserID:      42,
		BalanceCost: 1,
	}
	p := &postUsageBillingParams{
		User:    &User{ID: 42, Balance: 10},
		APIKey:  &APIKey{ID: 7},
		Account: &Account{ID: 99},
	}

	result, handled, err := wb.Apply(context.Background(), cmd, p, deps)
	require.NoError(t, err)
	require.True(t, handled)
	require.True(t, result.Applied)

	result, handled, err = wb.Apply(context.Background(), cmd, p, deps)
	require.NoError(t, err)
	require.True(t, handled)
	require.False(t, result.Applied)
	require.Equal(t, 1, wb.Stats().PendingBalanceKeys)
	require.Equal(t, uint64(1), wb.Stats().DedupSkippedTotal)
}

func TestUsageBillingWriteBehind_ConflictingDuplicateFails(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	deps := &billingDeps{userRepo: &usageBillingWriteBehindUserRepoStub{}}
	p := &postUsageBillingParams{
		User:    &User{ID: 42, Balance: 10},
		APIKey:  &APIKey{ID: 7},
		Account: &Account{ID: 99},
	}

	_, handled, err := wb.Apply(context.Background(), &UsageBillingCommand{
		RequestID:          "same-request",
		APIKeyID:           7,
		UserID:             42,
		BalanceCost:        1,
		RequestFingerprint: "fingerprint-a",
	}, p, deps)
	require.NoError(t, err)
	require.True(t, handled)

	_, handled, err = wb.Apply(context.Background(), &UsageBillingCommand{
		RequestID:          "same-request",
		APIKeyID:           7,
		UserID:             42,
		BalanceCost:        1,
		RequestFingerprint: "fingerprint-b",
	}, p, deps)
	require.True(t, handled)
	require.ErrorIs(t, err, ErrUsageBillingRequestConflict)
}

func TestUsageBillingWriteBehind_APIKeyQuotaShadowExhaustsBeforeFlush(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	apiKeyUpdater := &usageBillingWriteBehindAPIKeyUpdaterStub{}
	deps := &billingDeps{}
	apiKey := &APIKey{ID: 7, Quota: 5, QuotaUsed: 3}

	result, handled, err := wb.Apply(context.Background(), &UsageBillingCommand{
		RequestID:       "quota-request",
		APIKeyID:        7,
		UserID:          42,
		AccountID:       99,
		APIKeyQuotaCost: 2,
	}, &postUsageBillingParams{
		User:          &User{ID: 42, Balance: 10},
		APIKey:        apiKey,
		Account:       &Account{ID: 99},
		APIKeyService: apiKeyUpdater,
	}, deps)
	require.NoError(t, err)
	require.True(t, handled)
	require.True(t, result.APIKeyQuotaExhausted)
	require.True(t, wb.APIKeyQuotaExhausted(apiKey))
	require.Equal(t, 0, apiKeyUpdater.quotaCalls)
}

func TestUsageBillingWriteBehind_RequeuesOnlyUnflushedRemainder(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	userRepo := &usageBillingWriteBehindUserRepoStub{}
	accountRepo := &usageBillingWriteBehindAccountRepoStub{err: errors.New("account quota failed")}
	deps := &billingDeps{userRepo: userRepo, accountRepo: accountRepo}

	_, handled, err := wb.Apply(context.Background(), &UsageBillingCommand{
		RequestID:        "partial-failure",
		APIKeyID:         7,
		UserID:           42,
		AccountID:        99,
		BalanceCost:      1,
		AccountQuotaCost: 2,
	}, &postUsageBillingParams{
		User:    &User{ID: 42, Balance: 10},
		APIKey:  &APIKey{ID: 7},
		Account: &Account{ID: 99, Type: AccountTypeAPIKey},
	}, deps)
	require.NoError(t, err)
	require.True(t, handled)

	wb.Flush(context.Background(), deps)
	require.Equal(t, 1, userRepo.calls)
	require.Equal(t, 1, accountRepo.calls)
	stats := wb.Stats()
	require.Equal(t, 0, stats.PendingBalanceKeys)
	require.Equal(t, 1, stats.PendingAccountQuotaKeys)
	require.Equal(t, uint64(1), stats.FlushErrorTotal)

	accountRepo.err = nil
	wb.Flush(context.Background(), deps)
	require.Equal(t, 1, userRepo.calls)
	require.Equal(t, 2, accountRepo.calls)
	require.Eventually(t, func() bool {
		return wb.Stats().PendingAccountQuotaKeys == 0
	}, time.Second, 10*time.Millisecond)
}
