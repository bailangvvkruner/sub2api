package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type usageBillingWriteBehindUserRepoStub struct {
	UserRepository

	calls      int
	getCalls   int
	lastUserID int64
	lastAmount float64
	balance    float64
	err        error
}

func (s *usageBillingWriteBehindUserRepoStub) GetByID(ctx context.Context, id int64) (*User, error) {
	s.getCalls++
	if s.err != nil {
		return nil, s.err
	}
	return &User{ID: id, Balance: s.balance}, nil
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

type usageBillingWriteBehindRepoStub struct {
	calls   int
	lastCmd *UsageBillingCommand
	err     error
}

func (s *usageBillingWriteBehindRepoStub) Apply(ctx context.Context, cmd *UsageBillingCommand) (*UsageBillingApplyResult, error) {
	s.calls++
	s.lastCmd = cloneUsageBillingCommand(cmd)
	if s.err != nil {
		return nil, s.err
	}
	return &UsageBillingApplyResult{Applied: true}, nil
}

func (s *usageBillingWriteBehindRepoStub) ReserveBatchImageBalance(context.Context, *BatchImageBalanceHoldCommand) (*BatchImageBalanceHoldResult, error) {
	return nil, nil
}

func (s *usageBillingWriteBehindRepoStub) CaptureBatchImageBalance(context.Context, *BatchImageBalanceHoldCommand) (*BatchImageBalanceHoldResult, error) {
	return nil, nil
}

func (s *usageBillingWriteBehindRepoStub) ReleaseBatchImageBalance(context.Context, *BatchImageBalanceHoldCommand) (*BatchImageBalanceHoldResult, error) {
	return nil, nil
}

type usageBillingWriteBehindBalanceCacheStub struct {
	BillingCache

	mu       sync.Mutex
	balances map[int64]float64
	setCalls int
}

func newUsageBillingWriteBehindBalanceCacheStub(initial map[int64]float64) *usageBillingWriteBehindBalanceCacheStub {
	balances := make(map[int64]float64, len(initial))
	for userID, balance := range initial {
		balances[userID] = balance
	}
	return &usageBillingWriteBehindBalanceCacheStub{balances: balances}
}

func (s *usageBillingWriteBehindBalanceCacheStub) GetUserBalance(_ context.Context, userID int64) (float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	balance, ok := s.balances[userID]
	if !ok {
		return 0, errors.New("balance cache miss")
	}
	return balance, nil
}

func (s *usageBillingWriteBehindBalanceCacheStub) GetUserBalanceForTest(userID int64) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	balance, ok := s.balances[userID]
	return balance, ok
}

func (s *usageBillingWriteBehindBalanceCacheStub) SetUserBalance(_ context.Context, userID int64, balance float64) error {
	s.mu.Lock()
	s.balances[userID] = balance
	s.setCalls++
	s.mu.Unlock()
	return nil
}

func (s *usageBillingWriteBehindBalanceCacheStub) SetCallsForTest() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setCalls
}

func (s *usageBillingWriteBehindBalanceCacheStub) LocalBillingWriteThroughEnabled() bool {
	return false
}

func (s *usageBillingWriteBehindBalanceCacheStub) ApplyUserBalanceDeltaLocal(userID int64, delta float64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	balance, ok := s.balances[userID]
	if !ok {
		return false
	}
	s.balances[userID] = balance + delta
	return true
}

func newUsageBillingWriteBehindForTest() *UsageBillingWriteBehind {
	cfg := &config.Config{}
	cfg.Gateway.HotPath.UsageBillingWriteBehind = true
	cfg.Gateway.HotPath.UsageBillingFlushIntervalMs = 30000
	cfg.Idempotency.DefaultTTLSeconds = 60
	cfg.APIKeyAuth.L2TTLSeconds = 60
	return NewUsageBillingWriteBehind(cfg)
}

func TestUsageBillingWriteBehind_DeductsSequentiallyFromL1(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	cache := newUsageBillingWriteBehindBalanceCacheStub(map[int64]float64{42: 10})
	cacheService := &BillingCacheService{cache: cache}
	deps := &billingDeps{billingCacheService: cacheService}
	p := &postUsageBillingParams{
		Cost: &CostBreakdown{ActualCost: 1},
		User: &User{ID: 42, Balance: 999}, // Deliberately stale auth snapshot.
	}

	var balances []float64
	for _, requestID := range []string{"sequential-1", "sequential-2"} {
		result, handled, err := wb.Apply(context.Background(), &UsageBillingCommand{
			RequestID:   requestID,
			UserID:      42,
			BalanceCost: 1,
		}, p, deps)
		require.NoError(t, err)
		require.True(t, handled)
		require.NotNil(t, result.NewBalance)
		balances = append(balances, *result.NewBalance)

		// finalize must not apply the write-behind deduction a second time.
		syncBalanceCacheAfterDeduction(context.Background(), p, deps, result)
	}

	require.Equal(t, []float64{9, 8}, balances)
	balance, ok := cache.GetUserBalanceForTest(42)
	require.True(t, ok)
	require.Equal(t, 8.0, balance)
	require.Equal(t, 0, cache.SetCallsForTest(), "write-behind must use atomic deltas, not absolute balance writes")
}

func TestUsageBillingWriteBehind_ConcurrentDeductionsAreSerializedAgainstL1(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	cache := newUsageBillingWriteBehindBalanceCacheStub(map[int64]float64{42: 10})
	deps := &billingDeps{billingCacheService: &BillingCacheService{cache: cache}}
	p := &postUsageBillingParams{User: &User{ID: 42, Balance: 999}}

	const deductions = 8
	start := make(chan struct{})
	errCh := make(chan error, deductions)
	var wg sync.WaitGroup
	for i := 0; i < deductions; i++ {
		wg.Add(1)
		go func(request int) {
			defer wg.Done()
			<-start
			result, handled, err := wb.Apply(context.Background(), &UsageBillingCommand{
				RequestID:   "concurrent-" + string(rune('a'+request)),
				UserID:      42,
				BalanceCost: 1,
			}, p, deps)
			if err == nil && (!handled || result == nil || result.NewBalance == nil) {
				err = errors.New("deduction was not applied")
			}
			errCh <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}
	balance, ok := cache.GetUserBalanceForTest(42)
	require.True(t, ok)
	require.Equal(t, 2.0, balance)
	require.Equal(t, 0, cache.SetCallsForTest())
}

func TestUsageBillingWriteBehind_L1MissLoadsBeforeDelta(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	cache := newUsageBillingWriteBehindBalanceCacheStub(nil)
	userRepo := &usageBillingWriteBehindUserRepoStub{balance: 10}
	deps := &billingDeps{
		billingCacheService: &BillingCacheService{cache: cache, userRepo: userRepo},
		userRepo:            userRepo,
	}

	result, handled, err := wb.Apply(context.Background(), &UsageBillingCommand{
		RequestID:   "cache-miss",
		UserID:      42,
		BalanceCost: 1,
	}, &postUsageBillingParams{User: &User{ID: 42, Balance: 999}}, deps)
	require.NoError(t, err)
	require.True(t, handled)
	require.NotNil(t, result.NewBalance)
	require.Equal(t, 9.0, *result.NewBalance)
	require.Equal(t, 1, userRepo.getCalls)
	balance, ok := cache.GetUserBalanceForTest(42)
	require.True(t, ok)
	require.Equal(t, 9.0, balance)
	require.Equal(t, 1, cache.SetCallsForTest(), "DB fallback must synchronously seed L1 before the delta")
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

func TestApplyUsageBilling_ResolvesWriteBehindFromAPIKeyService(t *testing.T) {
	wb := newUsageBillingWriteBehindForTest()
	apiKeyService := &APIKeyService{}
	apiKeyService.SetUsageBillingWriteBehind(wb)

	applied, err := applyUsageBilling(context.Background(), "provider-request", nil, &postUsageBillingParams{
		Cost:          &CostBreakdown{},
		User:          &User{ID: 42, Balance: 10},
		APIKey:        &APIKey{ID: 7},
		Account:       &Account{ID: 99},
		APIKeyService: apiKeyService,
	}, &billingDeps{deferredService: &DeferredService{}}, nil)

	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 1, wb.Stats().PendingL1Entries)
}

func TestUsageBillingWriteBehind_FlushesL1CommandsThroughRepository(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.HotPath.UsageBillingWriteBehind = true
	cfg.Gateway.HotPath.UsageBillingFlushIntervalMs = 30000
	cfg.Idempotency.DefaultTTLSeconds = 60
	cfg.APIKeyAuth.L2TTLSeconds = 60
	repo := &usageBillingWriteBehindRepoStub{}
	wb := NewUsageBillingWriteBehindWithRedis(cfg, nil, repo)

	result, handled, err := wb.Apply(context.Background(), &UsageBillingCommand{
		RequestID: "zero-cost-request",
		APIKeyID:  7,
		UserID:    42,
		AccountID: 99,
	}, &postUsageBillingParams{
		User:    &User{ID: 42, Balance: 10},
		APIKey:  &APIKey{ID: 7},
		Account: &Account{ID: 99},
	}, &billingDeps{})
	require.NoError(t, err)
	require.True(t, handled)
	require.True(t, result.Applied)
	require.Equal(t, 1, wb.Stats().PendingL1Entries)
	require.Equal(t, 0, wb.Stats().PendingBalanceKeys)
	require.Equal(t, 0, repo.calls)

	wb.Flush(context.Background(), nil)

	require.Equal(t, 1, repo.calls)
	require.NotNil(t, repo.lastCmd)
	require.Equal(t, "zero-cost-request", repo.lastCmd.RequestID)
	stats := wb.Stats()
	require.Equal(t, 0, stats.PendingL1Entries)
	require.Equal(t, uint64(1), stats.FlushSuccessTotal)
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
