package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

const (
	defaultUsageBillingFlushInterval = 30 * time.Second
	usageBillingApplyTimeout         = 3 * time.Second
	usageBillingFlushMaxBatches      = 16
)

type usageBillingDedupEntry struct {
	fingerprint string
	expiresAt   time.Time
}

type usageBillingWriteBehindBatch struct {
	balances       map[int64]float64
	subscriptions  map[int64]float64
	apiKeyQuota    map[int64]usageBillingAPIKeyQuotaDelta
	apiKeyRate     map[int64]float64
	apiKeyUpdaters map[int64]APIKeyQuotaUpdater
	accountQuota   map[int64]float64
}

type usageBillingAPIKeyQuotaDelta struct {
	cost float64
}

type usageBillingAPIKeyQuotaShadow struct {
	used      float64
	quota     float64
	expiresAt time.Time
}

type UsageBillingWriteBehindStats struct {
	PendingBalanceKeys         int
	PendingSubscriptionKeys    int
	PendingAPIKeyQuotaKeys     int
	PendingAPIKeyRateKeys      int
	PendingAPIKeyUpdaterKeys   int
	PendingAccountQuotaKeys    int
	DedupEntries               int
	AppliedTotal               uint64
	DedupSkippedTotal          uint64
	FlushSuccessTotal          uint64
	FlushErrorTotal            uint64
	FlushBalanceKeysTotal      uint64
	FlushSubscriptionKeysTotal uint64
	FlushAPIKeyQuotaKeysTotal  uint64
	FlushAPIKeyRateKeysTotal   uint64
	FlushAccountQuotaKeysTotal uint64
}

type UsageBillingWriteBehind struct {
	cfg      *config.Config
	enabled  bool
	interval time.Duration
	stopCh   chan struct{}
	stopped  atomic.Bool
	started  atomic.Bool
	once     sync.Once
	wg       sync.WaitGroup

	mu             sync.Mutex
	depsMu         sync.RWMutex
	deps           *billingDeps
	balances       map[int64]float64
	subscriptions  map[int64]float64
	apiKeyQuota    map[int64]usageBillingAPIKeyQuotaDelta
	apiKeyRate     map[int64]float64
	apiKeyUpdaters map[int64]APIKeyQuotaUpdater
	accountQuota   map[int64]float64
	quotaShadow    map[int64]usageBillingAPIKeyQuotaShadow
	dedup          map[string]usageBillingDedupEntry

	appliedTotal               atomic.Uint64
	dedupSkippedTotal          atomic.Uint64
	flushSuccessTotal          atomic.Uint64
	flushErrorTotal            atomic.Uint64
	flushBalanceKeysTotal      atomic.Uint64
	flushSubscriptionKeysTotal atomic.Uint64
	flushAPIKeyQuotaKeysTotal  atomic.Uint64
	flushAPIKeyRateKeysTotal   atomic.Uint64
	flushAccountQuotaKeysTotal atomic.Uint64
}

func NewUsageBillingWriteBehind(cfg *config.Config) *UsageBillingWriteBehind {
	interval := defaultUsageBillingFlushInterval
	if cfg != nil && cfg.Gateway.HotPath.UsageBillingFlushIntervalMs > 0 {
		interval = time.Duration(cfg.Gateway.HotPath.UsageBillingFlushIntervalMs) * time.Millisecond
	}
	s := &UsageBillingWriteBehind{
		cfg:            cfg,
		enabled:        cfg != nil && cfg.Gateway.HotPath.UsageBillingWriteBehind,
		interval:       interval,
		stopCh:         make(chan struct{}),
		balances:       make(map[int64]float64),
		subscriptions:  make(map[int64]float64),
		apiKeyQuota:    make(map[int64]usageBillingAPIKeyQuotaDelta),
		apiKeyRate:     make(map[int64]float64),
		apiKeyUpdaters: make(map[int64]APIKeyQuotaUpdater),
		accountQuota:   make(map[int64]float64),
		quotaShadow:    make(map[int64]usageBillingAPIKeyQuotaShadow),
		dedup:          make(map[string]usageBillingDedupEntry),
	}
	return s
}

func (s *UsageBillingWriteBehind) Enabled() bool {
	return s != nil && s.enabled
}

func (s *UsageBillingWriteBehind) rememberDeps(deps *billingDeps) {
	if s == nil || deps == nil {
		return
	}
	s.depsMu.Lock()
	s.deps = deps
	s.depsMu.Unlock()
}

func (s *UsageBillingWriteBehind) currentDeps() *billingDeps {
	if s == nil {
		return nil
	}
	s.depsMu.RLock()
	defer s.depsMu.RUnlock()
	return s.deps
}

func (s *UsageBillingWriteBehind) APIKeyQuotaExhausted(apiKey *APIKey) bool {
	if !s.Enabled() || apiKey == nil || apiKey.Quota <= 0 {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	shadow, ok := s.quotaShadow[apiKey.ID]
	if ok && !shadow.expiresAt.After(now) {
		delete(s.quotaShadow, apiKey.ID)
		ok = false
	}
	used := apiKey.QuotaUsed
	if ok && shadow.used > used {
		used = shadow.used
	}
	return used >= apiKey.Quota
}

func (s *UsageBillingWriteBehind) Start() {
	if !s.Enabled() {
		return
	}
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Flush(context.Background(), nil)
			case <-s.stopCh:
				return
			}
		}
	}()
	logger.LegacyPrintf("usage_billing_write_behind", "[UsageBillingWriteBehind] started interval=%s", s.interval)
}

func (s *UsageBillingWriteBehind) Stop(deps *billingDeps) {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.stopped.Store(true)
		close(s.stopCh)
	})
	s.wg.Wait()
	s.Flush(context.Background(), deps)
}

func (s *UsageBillingWriteBehind) Apply(ctx context.Context, cmd *UsageBillingCommand, p *postUsageBillingParams, deps *billingDeps) (*UsageBillingApplyResult, bool, error) {
	if !s.Enabled() || cmd == nil || p == nil || deps == nil {
		return nil, false, nil
	}
	if s.stopped.Load() {
		return nil, false, nil
	}
	s.rememberDeps(deps)
	cmd.Normalize()
	if cmd.RequestID == "" {
		return nil, false, ErrUsageBillingRequestIDRequired
	}
	now := time.Now()
	dedupKey := usageBillingWriteBehindDedupKey(cmd)

	result := &UsageBillingApplyResult{Applied: true}
	if cmd.BalanceCost > 0 && p.User != nil {
		newBalance := p.User.Balance - cmd.BalanceCost
		result.NewBalance = &newBalance
		result.BalanceOverdrafted = p.User.Balance < cmd.BalanceCost
	}
	if cmd.AccountQuotaCost > 0 && p.Account != nil {
		result.QuotaState = buildOptimisticAccountQuotaState(p.Account, cmd.AccountQuotaCost)
	}

	s.mu.Lock()
	s.pruneDedupLocked(now)
	if existing, ok := s.dedup[dedupKey]; ok && existing.expiresAt.After(now) {
		if strings.TrimSpace(existing.fingerprint) != strings.TrimSpace(cmd.RequestFingerprint) {
			s.mu.Unlock()
			return nil, true, ErrUsageBillingRequestConflict
		}
		s.dedupSkippedTotal.Add(1)
		s.mu.Unlock()
		return &UsageBillingApplyResult{Applied: false}, true, nil
	}
	s.dedup[dedupKey] = usageBillingDedupEntry{
		fingerprint: strings.TrimSpace(cmd.RequestFingerprint),
		expiresAt:   now.Add(s.dedupTTL()),
	}
	if cmd.BalanceCost > 0 {
		s.balances[cmd.UserID] += cmd.BalanceCost
	}
	if cmd.SubscriptionCost > 0 && cmd.SubscriptionID != nil {
		s.subscriptions[*cmd.SubscriptionID] += cmd.SubscriptionCost
	}
	if cmd.APIKeyQuotaCost > 0 {
		item := s.apiKeyQuota[cmd.APIKeyID]
		item.cost += cmd.APIKeyQuotaCost
		if p.APIKey != nil {
			shadow := s.quotaShadow[cmd.APIKeyID]
			if shadow.used < p.APIKey.QuotaUsed {
				shadow.used = p.APIKey.QuotaUsed
			}
			shadow.used += cmd.APIKeyQuotaCost
			shadow.quota = p.APIKey.Quota
			shadow.expiresAt = now.Add(s.quotaShadowTTL())
			s.quotaShadow[cmd.APIKeyID] = shadow
			result.APIKeyQuotaExhausted = shadow.quota > 0 && shadow.used >= shadow.quota
		}
		s.apiKeyQuota[cmd.APIKeyID] = item
		if p.APIKeyService != nil {
			s.apiKeyUpdaters[cmd.APIKeyID] = p.APIKeyService
		}
	}
	if cmd.APIKeyRateLimitCost > 0 {
		s.apiKeyRate[cmd.APIKeyID] += cmd.APIKeyRateLimitCost
		if p.APIKeyService != nil {
			s.apiKeyUpdaters[cmd.APIKeyID] = p.APIKeyService
		}
	}
	if cmd.AccountQuotaCost > 0 {
		s.accountQuota[cmd.AccountID] += cmd.AccountQuotaCost
	}
	s.appliedTotal.Add(1)
	s.mu.Unlock()

	return result, true, nil
}

func (s *UsageBillingWriteBehind) Flush(parentCtx context.Context, deps *billingDeps) {
	if s == nil {
		return
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	for i := 0; i < usageBillingFlushMaxBatches; i++ {
		batch := s.takeBatch()
		if batch.empty() {
			return
		}
		balanceKeys := len(batch.balances)
		subscriptionKeys := len(batch.subscriptions)
		apiKeyQuotaKeys := len(batch.apiKeyQuota)
		apiKeyRateKeys := len(batch.apiKeyRate)
		accountQuotaKeys := len(batch.accountQuota)
		if err := s.flushBatch(parentCtx, deps, batch); err != nil {
			s.requeue(batch)
			s.flushErrorTotal.Add(1)
			logger.LegacyPrintf("usage_billing_write_behind", "[UsageBillingWriteBehind] ALERT flush failed: %v", err)
			return
		}
		s.flushSuccessTotal.Add(1)
		s.flushBalanceKeysTotal.Add(uint64(balanceKeys))
		s.flushSubscriptionKeysTotal.Add(uint64(subscriptionKeys))
		s.flushAPIKeyQuotaKeysTotal.Add(uint64(apiKeyQuotaKeys))
		s.flushAPIKeyRateKeysTotal.Add(uint64(apiKeyRateKeys))
		s.flushAccountQuotaKeysTotal.Add(uint64(accountQuotaKeys))
	}
	logger.LegacyPrintf("usage_billing_write_behind", "[UsageBillingWriteBehind] single flush reached batch cap=%d", usageBillingFlushMaxBatches)
}

func (s *UsageBillingWriteBehind) Stats() UsageBillingWriteBehindStats {
	if s == nil {
		return UsageBillingWriteBehindStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return UsageBillingWriteBehindStats{
		PendingBalanceKeys:         len(s.balances),
		PendingSubscriptionKeys:    len(s.subscriptions),
		PendingAPIKeyQuotaKeys:     len(s.apiKeyQuota),
		PendingAPIKeyRateKeys:      len(s.apiKeyRate),
		PendingAPIKeyUpdaterKeys:   len(s.apiKeyUpdaters),
		PendingAccountQuotaKeys:    len(s.accountQuota),
		DedupEntries:               len(s.dedup),
		AppliedTotal:               s.appliedTotal.Load(),
		DedupSkippedTotal:          s.dedupSkippedTotal.Load(),
		FlushSuccessTotal:          s.flushSuccessTotal.Load(),
		FlushErrorTotal:            s.flushErrorTotal.Load(),
		FlushBalanceKeysTotal:      s.flushBalanceKeysTotal.Load(),
		FlushSubscriptionKeysTotal: s.flushSubscriptionKeysTotal.Load(),
		FlushAPIKeyQuotaKeysTotal:  s.flushAPIKeyQuotaKeysTotal.Load(),
		FlushAPIKeyRateKeysTotal:   s.flushAPIKeyRateKeysTotal.Load(),
		FlushAccountQuotaKeysTotal: s.flushAccountQuotaKeysTotal.Load(),
	}
}

func (s *UsageBillingWriteBehind) takeBatch() usageBillingWriteBehindBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.pruneDedupLocked(now)
	batch := usageBillingWriteBehindBatch{
		balances:       s.balances,
		subscriptions:  s.subscriptions,
		apiKeyQuota:    s.apiKeyQuota,
		apiKeyRate:     s.apiKeyRate,
		apiKeyUpdaters: s.apiKeyUpdaters,
		accountQuota:   s.accountQuota,
	}
	s.balances = make(map[int64]float64)
	s.subscriptions = make(map[int64]float64)
	s.apiKeyQuota = make(map[int64]usageBillingAPIKeyQuotaDelta)
	s.apiKeyRate = make(map[int64]float64)
	s.apiKeyUpdaters = make(map[int64]APIKeyQuotaUpdater)
	s.accountQuota = make(map[int64]float64)
	return batch
}

func (s *UsageBillingWriteBehind) requeue(batch usageBillingWriteBehindBatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for userID, cost := range batch.balances {
		s.balances[userID] += cost
	}
	for id, cost := range batch.subscriptions {
		s.subscriptions[id] += cost
	}
	for keyID, delta := range batch.apiKeyQuota {
		existing := s.apiKeyQuota[keyID]
		existing.cost += delta.cost
		s.apiKeyQuota[keyID] = existing
	}
	for keyID, cost := range batch.apiKeyRate {
		s.apiKeyRate[keyID] += cost
	}
	for keyID, updater := range batch.apiKeyUpdaters {
		if _, ok := batch.apiKeyQuota[keyID]; !ok {
			if _, ok := batch.apiKeyRate[keyID]; !ok {
				continue
			}
		}
		if updater != nil && s.apiKeyUpdaters[keyID] == nil {
			s.apiKeyUpdaters[keyID] = updater
		}
	}
	for accountID, cost := range batch.accountQuota {
		s.accountQuota[accountID] += cost
	}
}

func (s *UsageBillingWriteBehind) flushBatch(parentCtx context.Context, deps *billingDeps, batch usageBillingWriteBehindBatch) error {
	if batch.empty() {
		return nil
	}
	if deps == nil {
		deps = s.currentDeps()
	}
	if deps == nil {
		return errors.New("usage billing write-behind deps nil")
	}
	ctx, cancel := context.WithTimeout(parentCtx, usageBillingApplyTimeout)
	defer cancel()

	if len(batch.balances) > 0 && deps.userRepo == nil {
		return errors.New("usage billing write-behind user repo nil")
	}
	for userID, cost := range batch.balances {
		if cost <= 0 {
			delete(batch.balances, userID)
			continue
		}
		if err := deps.userRepo.DeductBalance(ctx, userID, cost); err != nil {
			return err
		}
		delete(batch.balances, userID)
	}

	if len(batch.subscriptions) > 0 && deps.userSubRepo == nil {
		return errors.New("usage billing write-behind subscription repo nil")
	}
	for id, cost := range batch.subscriptions {
		if cost <= 0 {
			delete(batch.subscriptions, id)
			continue
		}
		if err := deps.userSubRepo.IncrementUsage(ctx, id, cost); err != nil {
			return err
		}
		delete(batch.subscriptions, id)
	}

	for keyID, delta := range batch.apiKeyQuota {
		if delta.cost <= 0 {
			delete(batch.apiKeyQuota, keyID)
			continue
		}
		updater := batch.apiKeyUpdaters[keyID]
		if updater == nil {
			return errors.New("usage billing write-behind api key quota updater nil")
		}
		if err := updater.UpdateQuotaUsed(ctx, keyID, delta.cost); err != nil {
			return err
		}
		delete(batch.apiKeyQuota, keyID)
	}
	for keyID, cost := range batch.apiKeyRate {
		if cost <= 0 {
			delete(batch.apiKeyRate, keyID)
			continue
		}
		updater := batch.apiKeyUpdaters[keyID]
		if updater == nil {
			return errors.New("usage billing write-behind api key rate updater nil")
		}
		if err := updater.UpdateRateLimitUsage(ctx, keyID, cost); err != nil {
			return err
		}
		delete(batch.apiKeyRate, keyID)
	}
	if len(batch.accountQuota) > 0 && deps.accountRepo == nil {
		return errors.New("usage billing write-behind account repo nil")
	}
	for accountID, cost := range batch.accountQuota {
		if cost <= 0 {
			delete(batch.accountQuota, accountID)
			continue
		}
		if err := deps.accountRepo.IncrementQuotaUsed(ctx, accountID, cost); err != nil {
			return err
		}
		delete(batch.accountQuota, accountID)
	}
	return nil
}

func (b usageBillingWriteBehindBatch) empty() bool {
	return len(b.balances) == 0 &&
		len(b.subscriptions) == 0 &&
		len(b.apiKeyQuota) == 0 &&
		len(b.apiKeyRate) == 0 &&
		len(b.accountQuota) == 0
}

func (s *UsageBillingWriteBehind) pruneDedupLocked(now time.Time) {
	for key, entry := range s.dedup {
		if !entry.expiresAt.After(now) {
			delete(s.dedup, key)
		}
	}
	for key, entry := range s.quotaShadow {
		if !entry.expiresAt.After(now) {
			delete(s.quotaShadow, key)
		}
	}
}

func (s *UsageBillingWriteBehind) dedupTTL() time.Duration {
	if s == nil || s.cfg == nil || s.cfg.Idempotency.DefaultTTLSeconds <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(s.cfg.Idempotency.DefaultTTLSeconds) * time.Second
}

func (s *UsageBillingWriteBehind) quotaShadowTTL() time.Duration {
	if s == nil || s.cfg == nil || s.cfg.APIKeyAuth.L2TTLSeconds <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(s.cfg.APIKeyAuth.L2TTLSeconds) * time.Second
}

func usageBillingWriteBehindDedupKey(cmd *UsageBillingCommand) string {
	if cmd == nil {
		return ""
	}
	return strings.TrimSpace(cmd.RequestID) + ":" + strconv.FormatInt(cmd.APIKeyID, 10)
}

func buildOptimisticAccountQuotaState(account *Account, cost float64) *AccountQuotaState {
	if account == nil {
		return nil
	}
	state := &AccountQuotaState{
		TotalUsed:   account.GetQuotaUsed() + cost,
		TotalLimit:  account.GetQuotaLimit(),
		DailyUsed:   account.GetQuotaDailyUsed() + cost,
		DailyLimit:  account.GetQuotaDailyLimit(),
		WeeklyUsed:  account.GetQuotaWeeklyUsed() + cost,
		WeeklyLimit: account.GetQuotaWeeklyLimit(),
	}
	return state
}
