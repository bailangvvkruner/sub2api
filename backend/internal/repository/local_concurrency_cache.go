package repository

import (
	"context"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type localConcurrencyCache struct {
	mu                  sync.Mutex
	slotTTL             time.Duration
	waitQueueTTL        time.Duration
	lastFullCleanup     time.Time
	accountSlots        map[int64]map[string]time.Time
	userSlots           map[int64]map[string]time.Time
	accountWaitCounters map[int64]localWaitCounter
	userWaitCounters    map[int64]localWaitCounter
}

type localWaitCounter struct {
	count     int
	expiresAt time.Time
}

const localConcurrencyFullCleanupInterval = time.Minute

func NewLocalConcurrencyCache(slotTTLMinutes int, waitQueueTTLSeconds int) service.ConcurrencyCache {
	if slotTTLMinutes <= 0 {
		slotTTLMinutes = defaultSlotTTLMinutes
	}
	if waitQueueTTLSeconds <= 0 {
		waitQueueTTLSeconds = slotTTLMinutes * 60
	}
	return &localConcurrencyCache{
		slotTTL:             time.Duration(slotTTLMinutes) * time.Minute,
		waitQueueTTL:        time.Duration(waitQueueTTLSeconds) * time.Second,
		accountSlots:        make(map[int64]map[string]time.Time),
		userSlots:           make(map[int64]map[string]time.Time),
		accountWaitCounters: make(map[int64]localWaitCounter),
		userWaitCounters:    make(map[int64]localWaitCounter),
	}
}

func (c *localConcurrencyCache) AcquireAccountSlot(ctx context.Context, accountID int64, maxConcurrency int, requestID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.acquireSlot(c.accountSlots, accountID, maxConcurrency, requestID, time.Now()), nil
}

func (c *localConcurrencyCache) ReleaseAccountSlot(ctx context.Context, accountID int64, requestID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releaseSlot(c.accountSlots, accountID, requestID)
	return nil
}

func (c *localConcurrencyCache) GetAccountConcurrency(ctx context.Context, accountID int64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.slotCount(c.accountSlots, accountID, time.Now()), nil
}

func (c *localConcurrencyCache) GetAccountConcurrencyBatch(ctx context.Context, accountIDs []int64) (map[int64]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make(map[int64]int, len(accountIDs))
	for _, accountID := range accountIDs {
		result[accountID] = c.slotCount(c.accountSlots, accountID, now)
	}
	return result, nil
}

func (c *localConcurrencyCache) IncrementAccountWaitCount(ctx context.Context, accountID int64, maxWait int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.incrementWaitCounter(c.accountWaitCounters, accountID, maxWait, time.Now()), nil
}

func (c *localConcurrencyCache) DecrementAccountWaitCount(ctx context.Context, accountID int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decrementWaitCounter(c.accountWaitCounters, accountID, time.Now())
	return nil
}

func (c *localConcurrencyCache) GetAccountWaitingCount(ctx context.Context, accountID int64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.waitCount(c.accountWaitCounters, accountID, time.Now()), nil
}

func (c *localConcurrencyCache) AcquireUserSlot(ctx context.Context, userID int64, maxConcurrency int, requestID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.acquireSlot(c.userSlots, userID, maxConcurrency, requestID, time.Now()), nil
}

func (c *localConcurrencyCache) ReleaseUserSlot(ctx context.Context, userID int64, requestID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releaseSlot(c.userSlots, userID, requestID)
	return nil
}

func (c *localConcurrencyCache) GetUserConcurrency(ctx context.Context, userID int64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.slotCount(c.userSlots, userID, time.Now()), nil
}

func (c *localConcurrencyCache) IncrementWaitCount(ctx context.Context, userID int64, maxWait int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.incrementWaitCounter(c.userWaitCounters, userID, maxWait, time.Now()), nil
}

func (c *localConcurrencyCache) DecrementWaitCount(ctx context.Context, userID int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decrementWaitCounter(c.userWaitCounters, userID, time.Now())
	return nil
}

func (c *localConcurrencyCache) GetAccountsLoadBatch(ctx context.Context, accounts []service.AccountWithConcurrency) (map[int64]*service.AccountLoadInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	loadMap := make(map[int64]*service.AccountLoadInfo, len(accounts))
	for _, account := range accounts {
		currentConcurrency := c.slotCount(c.accountSlots, account.ID, now)
		waitingCount := c.waitCount(c.accountWaitCounters, account.ID, now)
		loadRate := 0
		if account.MaxConcurrency > 0 {
			loadRate = (currentConcurrency + waitingCount) * 100 / account.MaxConcurrency
		}
		loadMap[account.ID] = &service.AccountLoadInfo{
			AccountID:          account.ID,
			CurrentConcurrency: currentConcurrency,
			WaitingCount:       waitingCount,
			LoadRate:           loadRate,
		}
	}
	return loadMap, nil
}

func (c *localConcurrencyCache) GetUsersLoadBatch(ctx context.Context, users []service.UserWithConcurrency) (map[int64]*service.UserLoadInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	loadMap := make(map[int64]*service.UserLoadInfo, len(users))
	for _, user := range users {
		currentConcurrency := c.slotCount(c.userSlots, user.ID, now)
		waitingCount := c.waitCount(c.userWaitCounters, user.ID, now)
		loadRate := 0
		if user.MaxConcurrency > 0 {
			loadRate = (currentConcurrency + waitingCount) * 100 / user.MaxConcurrency
		}
		loadMap[user.ID] = &service.UserLoadInfo{
			UserID:             user.ID,
			CurrentConcurrency: currentConcurrency,
			WaitingCount:       waitingCount,
			LoadRate:           loadRate,
		}
	}
	return loadMap, nil
}

func (c *localConcurrencyCache) CleanupExpiredAccountSlots(ctx context.Context, accountID int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupSlots(c.accountSlots, accountID, time.Now())
	return nil
}

func (c *localConcurrencyCache) CleanupStaleProcessSlots(ctx context.Context, activeRequestPrefix string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupAllExpired(time.Now())
	return nil
}

func (c *localConcurrencyCache) acquireSlot(slotsByOwner map[int64]map[string]time.Time, ownerID int64, maxConcurrency int, requestID string, now time.Time) bool {
	if maxConcurrency <= 0 {
		return false
	}
	c.maybeCleanupAllExpired(now)
	c.cleanupSlots(slotsByOwner, ownerID, now)
	slots := slotsByOwner[ownerID]
	if slots == nil {
		slots = make(map[string]time.Time)
		slotsByOwner[ownerID] = slots
	}
	expiresAt := now.Add(c.slotTTL)
	if _, exists := slots[requestID]; exists {
		slots[requestID] = expiresAt
		return true
	}
	if len(slots) >= maxConcurrency {
		return false
	}
	slots[requestID] = expiresAt
	return true
}

func (c *localConcurrencyCache) releaseSlot(slotsByOwner map[int64]map[string]time.Time, ownerID int64, requestID string) {
	slots := slotsByOwner[ownerID]
	if slots == nil {
		return
	}
	delete(slots, requestID)
	if len(slots) == 0 {
		delete(slotsByOwner, ownerID)
	}
}

func (c *localConcurrencyCache) slotCount(slotsByOwner map[int64]map[string]time.Time, ownerID int64, now time.Time) int {
	c.maybeCleanupAllExpired(now)
	c.cleanupSlots(slotsByOwner, ownerID, now)
	return len(slotsByOwner[ownerID])
}

func (c *localConcurrencyCache) cleanupSlots(slotsByOwner map[int64]map[string]time.Time, ownerID int64, now time.Time) {
	slots := slotsByOwner[ownerID]
	for requestID, expiresAt := range slots {
		if !expiresAt.After(now) {
			delete(slots, requestID)
		}
	}
	if len(slots) == 0 {
		delete(slotsByOwner, ownerID)
	}
}

func (c *localConcurrencyCache) incrementWaitCounter(counters map[int64]localWaitCounter, ownerID int64, maxWait int, now time.Time) bool {
	if maxWait <= 0 {
		return false
	}
	c.maybeCleanupAllExpired(now)
	counter := c.liveWaitCounter(counters, ownerID, now)
	if counter.count >= maxWait {
		return false
	}
	counter.count++
	counter.expiresAt = now.Add(c.waitQueueTTL)
	counters[ownerID] = counter
	return true
}

func (c *localConcurrencyCache) decrementWaitCounter(counters map[int64]localWaitCounter, ownerID int64, now time.Time) {
	counter := c.liveWaitCounter(counters, ownerID, now)
	if counter.count <= 1 {
		delete(counters, ownerID)
		return
	}
	counter.count--
	counters[ownerID] = counter
}

func (c *localConcurrencyCache) waitCount(counters map[int64]localWaitCounter, ownerID int64, now time.Time) int {
	c.maybeCleanupAllExpired(now)
	counter := c.liveWaitCounter(counters, ownerID, now)
	return counter.count
}

func (c *localConcurrencyCache) liveWaitCounter(counters map[int64]localWaitCounter, ownerID int64, now time.Time) localWaitCounter {
	counter := counters[ownerID]
	if counter.count <= 0 || !counter.expiresAt.After(now) {
		delete(counters, ownerID)
		return localWaitCounter{}
	}
	return counter
}

func (c *localConcurrencyCache) maybeCleanupAllExpired(now time.Time) {
	if !c.lastFullCleanup.IsZero() && now.Sub(c.lastFullCleanup) < localConcurrencyFullCleanupInterval {
		return
	}
	c.lastFullCleanup = now
	c.cleanupAllExpired(now)
}

func (c *localConcurrencyCache) cleanupAllExpired(now time.Time) {
	c.cleanupSlotOwners(c.accountSlots, now)
	c.cleanupSlotOwners(c.userSlots, now)
	c.cleanupWaitCounters(c.accountWaitCounters, now)
	c.cleanupWaitCounters(c.userWaitCounters, now)
}

func (c *localConcurrencyCache) cleanupSlotOwners(slotsByOwner map[int64]map[string]time.Time, now time.Time) {
	for ownerID := range slotsByOwner {
		c.cleanupSlots(slotsByOwner, ownerID, now)
	}
}

func (c *localConcurrencyCache) cleanupWaitCounters(counters map[int64]localWaitCounter, now time.Time) {
	for ownerID, counter := range counters {
		if counter.count <= 0 || !counter.expiresAt.After(now) {
			delete(counters, ownerID)
		}
	}
}
