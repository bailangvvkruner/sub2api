package repository

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

const (
	defaultLocalBillingCacheMaxEntries = 262144
	minLocalBillingCacheMaxEntries     = 1024
)

type localBillingCache struct {
	next service.BillingCache

	maxEntries int
	clock      func() time.Time

	balanceMu sync.Mutex
	balances  map[int64]localBalanceEntry

	subMu         sync.Mutex
	subscriptions map[localSubscriptionKey]localSubscriptionEntry

	rateMu     sync.Mutex
	rateLimits map[int64]localRateLimitEntry

	quotaMu    sync.Mutex
	quotas     map[localQuotaKey]localQuotaEntry
	quotaDirty map[localQuotaKey]struct{}

	accessSeq atomic.Uint64
}

type localBalanceEntry struct {
	value    float64
	expires  time.Time
	accessed uint64
}

type localSubscriptionKey struct {
	userID  int64
	groupID int64
}

type localSubscriptionEntry struct {
	value    *service.SubscriptionCacheData
	expires  time.Time
	accessed uint64
}

type localRateLimitEntry struct {
	value    *service.APIKeyRateLimitCacheData
	expires  time.Time
	accessed uint64
}

type localQuotaKey struct {
	userID   int64
	platform string
}

type localQuotaEntry struct {
	value    *service.UserPlatformQuotaCacheEntry
	expires  time.Time
	accessed uint64
}

func newLocalBillingCache(next service.BillingCache, maxEntries int) service.BillingCache {
	if maxEntries <= 0 {
		maxEntries = defaultLocalBillingCacheMaxEntries
	}
	if maxEntries < minLocalBillingCacheMaxEntries {
		maxEntries = minLocalBillingCacheMaxEntries
	}
	return &localBillingCache{
		next:          next,
		maxEntries:    maxEntries,
		clock:         time.Now,
		balances:      make(map[int64]localBalanceEntry),
		subscriptions: make(map[localSubscriptionKey]localSubscriptionEntry),
		rateLimits:    make(map[int64]localRateLimitEntry),
		quotas:        make(map[localQuotaKey]localQuotaEntry),
		quotaDirty:    make(map[localQuotaKey]struct{}),
	}
}

func (c *localBillingCache) nextAccess() uint64 {
	return c.accessSeq.Add(1)
}

func localBillingTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return billingCacheTTL
	}
	return ttl
}

func (c *localBillingCache) evictBalancesLocked(now time.Time) {
	if len(c.balances) <= c.maxEntries {
		return
	}
	for key, entry := range c.balances {
		if !entry.expires.After(now) {
			delete(c.balances, key)
		}
	}
	for len(c.balances) > c.maxEntries {
		var victim int64
		var victimAccess uint64 = math.MaxUint64
		for key, entry := range c.balances {
			if entry.accessed < victimAccess {
				victim = key
				victimAccess = entry.accessed
			}
		}
		delete(c.balances, victim)
	}
}

func (c *localBillingCache) evictSubscriptionsLocked(now time.Time) {
	if len(c.subscriptions) <= c.maxEntries {
		return
	}
	for key, entry := range c.subscriptions {
		if !entry.expires.After(now) {
			delete(c.subscriptions, key)
		}
	}
	for len(c.subscriptions) > c.maxEntries {
		var victim localSubscriptionKey
		var victimAccess uint64 = math.MaxUint64
		for key, entry := range c.subscriptions {
			if entry.accessed < victimAccess {
				victim = key
				victimAccess = entry.accessed
			}
		}
		delete(c.subscriptions, victim)
	}
}

func (c *localBillingCache) evictRateLimitsLocked(now time.Time) {
	if len(c.rateLimits) <= c.maxEntries {
		return
	}
	for key, entry := range c.rateLimits {
		if !entry.expires.After(now) {
			delete(c.rateLimits, key)
		}
	}
	for len(c.rateLimits) > c.maxEntries {
		var victim int64
		var victimAccess uint64 = math.MaxUint64
		for key, entry := range c.rateLimits {
			if entry.accessed < victimAccess {
				victim = key
				victimAccess = entry.accessed
			}
		}
		delete(c.rateLimits, victim)
	}
}

func (c *localBillingCache) evictQuotasLocked(now time.Time) {
	if len(c.quotas) <= c.maxEntries {
		return
	}
	for key, entry := range c.quotas {
		if !entry.expires.After(now) {
			delete(c.quotas, key)
			delete(c.quotaDirty, key)
		}
	}
	for len(c.quotas) > c.maxEntries {
		var victim localQuotaKey
		var victimAccess uint64 = math.MaxUint64
		for key, entry := range c.quotas {
			if entry.accessed < victimAccess {
				victim = key
				victimAccess = entry.accessed
			}
		}
		delete(c.quotas, victim)
		delete(c.quotaDirty, victim)
	}
}

func (c *localBillingCache) GetUserBalance(ctx context.Context, userID int64) (float64, error) {
	now := c.clock()
	c.balanceMu.Lock()
	if entry, ok := c.balances[userID]; ok {
		if entry.expires.After(now) {
			entry.accessed = c.nextAccess()
			c.balances[userID] = entry
			c.balanceMu.Unlock()
			return entry.value, nil
		}
		delete(c.balances, userID)
	}
	c.balanceMu.Unlock()

	if c.next == nil {
		return 0, redis.Nil
	}
	balance, err := c.next.GetUserBalance(ctx, userID)
	if err != nil {
		return 0, err
	}
	c.setBalanceLocal(userID, balance, billingCacheTTL)
	return balance, nil
}

func (c *localBillingCache) SetUserBalance(ctx context.Context, userID int64, balance float64) error {
	c.setBalanceLocal(userID, balance, billingCacheTTL)
	if c.next == nil {
		return nil
	}
	return c.next.SetUserBalance(ctx, userID, balance)
}

func (c *localBillingCache) setBalanceLocal(userID int64, balance float64, ttl time.Duration) {
	now := c.clock()
	c.balanceMu.Lock()
	c.balances[userID] = localBalanceEntry{
		value:    balance,
		expires:  now.Add(localBillingTTL(ttl)),
		accessed: c.nextAccess(),
	}
	c.evictBalancesLocked(now)
	c.balanceMu.Unlock()
}

func (c *localBillingCache) DeductUserBalance(ctx context.Context, userID int64, amount float64) error {
	c.balanceMu.Lock()
	if entry, ok := c.balances[userID]; ok {
		entry.value -= amount
		entry.expires = c.clock().Add(billingCacheTTL)
		entry.accessed = c.nextAccess()
		c.balances[userID] = entry
	}
	c.balanceMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.DeductUserBalance(ctx, userID, amount)
}

func (c *localBillingCache) InvalidateUserBalance(ctx context.Context, userID int64) error {
	c.balanceMu.Lock()
	delete(c.balances, userID)
	c.balanceMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.InvalidateUserBalance(ctx, userID)
}

func (c *localBillingCache) GetSubscriptionCache(ctx context.Context, userID, groupID int64) (*service.SubscriptionCacheData, error) {
	key := localSubscriptionKey{userID: userID, groupID: groupID}
	now := c.clock()
	c.subMu.Lock()
	if entry, ok := c.subscriptions[key]; ok {
		if entry.expires.After(now) {
			entry.accessed = c.nextAccess()
			c.subscriptions[key] = entry
			out := cloneSubscriptionCacheData(entry.value)
			c.subMu.Unlock()
			return out, nil
		}
		delete(c.subscriptions, key)
	}
	c.subMu.Unlock()

	if c.next == nil {
		return nil, redis.Nil
	}
	data, err := c.next.GetSubscriptionCache(ctx, userID, groupID)
	if err != nil {
		return nil, err
	}
	c.setSubscriptionLocal(key, data, billingCacheTTL)
	return cloneSubscriptionCacheData(data), nil
}

func (c *localBillingCache) SetSubscriptionCache(ctx context.Context, userID, groupID int64, data *service.SubscriptionCacheData) error {
	if data != nil {
		c.setSubscriptionLocal(localSubscriptionKey{userID: userID, groupID: groupID}, data, billingCacheTTL)
	}
	if c.next == nil {
		return nil
	}
	return c.next.SetSubscriptionCache(ctx, userID, groupID, data)
}

func (c *localBillingCache) setSubscriptionLocal(key localSubscriptionKey, data *service.SubscriptionCacheData, ttl time.Duration) {
	if data == nil {
		return
	}
	now := c.clock()
	c.subMu.Lock()
	c.subscriptions[key] = localSubscriptionEntry{
		value:    cloneSubscriptionCacheData(data),
		expires:  now.Add(localBillingTTL(ttl)),
		accessed: c.nextAccess(),
	}
	c.evictSubscriptionsLocked(now)
	c.subMu.Unlock()
}

func (c *localBillingCache) UpdateSubscriptionUsage(ctx context.Context, userID, groupID int64, cost float64) error {
	key := localSubscriptionKey{userID: userID, groupID: groupID}
	c.subMu.Lock()
	if entry, ok := c.subscriptions[key]; ok && entry.value != nil {
		entry.value.DailyUsage += cost
		entry.value.WeeklyUsage += cost
		entry.value.MonthlyUsage += cost
		entry.expires = c.clock().Add(billingCacheTTL)
		entry.accessed = c.nextAccess()
		c.subscriptions[key] = entry
	}
	c.subMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.UpdateSubscriptionUsage(ctx, userID, groupID, cost)
}

func (c *localBillingCache) InvalidateSubscriptionCache(ctx context.Context, userID, groupID int64) error {
	c.subMu.Lock()
	delete(c.subscriptions, localSubscriptionKey{userID: userID, groupID: groupID})
	c.subMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.InvalidateSubscriptionCache(ctx, userID, groupID)
}

func (c *localBillingCache) GetAPIKeyRateLimit(ctx context.Context, keyID int64) (*service.APIKeyRateLimitCacheData, error) {
	now := c.clock()
	c.rateMu.Lock()
	if entry, ok := c.rateLimits[keyID]; ok {
		if entry.expires.After(now) {
			entry.accessed = c.nextAccess()
			c.rateLimits[keyID] = entry
			out := cloneRateLimitCacheData(entry.value)
			c.rateMu.Unlock()
			return out, nil
		}
		delete(c.rateLimits, keyID)
	}
	c.rateMu.Unlock()

	if c.next == nil {
		return nil, redis.Nil
	}
	data, err := c.next.GetAPIKeyRateLimit(ctx, keyID)
	if err != nil {
		return nil, err
	}
	c.setRateLimitLocal(keyID, data, rateLimitCacheTTL)
	return cloneRateLimitCacheData(data), nil
}

func (c *localBillingCache) SetAPIKeyRateLimit(ctx context.Context, keyID int64, data *service.APIKeyRateLimitCacheData) error {
	if data != nil {
		c.setRateLimitLocal(keyID, data, rateLimitCacheTTL)
	}
	if c.next == nil {
		return nil
	}
	return c.next.SetAPIKeyRateLimit(ctx, keyID, data)
}

func (c *localBillingCache) setRateLimitLocal(keyID int64, data *service.APIKeyRateLimitCacheData, ttl time.Duration) {
	if data == nil {
		return
	}
	now := c.clock()
	c.rateMu.Lock()
	c.rateLimits[keyID] = localRateLimitEntry{
		value:    cloneRateLimitCacheData(data),
		expires:  now.Add(localBillingTTL(ttl)),
		accessed: c.nextAccess(),
	}
	c.evictRateLimitsLocked(now)
	c.rateMu.Unlock()
}

func (c *localBillingCache) UpdateAPIKeyRateLimitUsage(ctx context.Context, keyID int64, cost float64) error {
	now := c.clock()
	c.rateMu.Lock()
	if entry, ok := c.rateLimits[keyID]; ok && entry.value != nil {
		updateLocalRateLimitWindow(&entry.value.Usage5h, &entry.value.Window5h, cost, now, service.RateLimitWindow5h)
		updateLocalRateLimitWindow(&entry.value.Usage1d, &entry.value.Window1d, cost, now, service.RateLimitWindow1d)
		updateLocalRateLimitWindow(&entry.value.Usage7d, &entry.value.Window7d, cost, now, service.RateLimitWindow7d)
		entry.expires = now.Add(rateLimitCacheTTL)
		entry.accessed = c.nextAccess()
		c.rateLimits[keyID] = entry
	}
	c.rateMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.UpdateAPIKeyRateLimitUsage(ctx, keyID, cost)
}

func updateLocalRateLimitWindow(usage *float64, window *int64, cost float64, now time.Time, duration time.Duration) {
	if window == nil || usage == nil {
		return
	}
	if *window <= 0 || now.Unix()-*window >= int64(duration.Seconds()) {
		*usage = cost
		*window = now.Unix()
		return
	}
	*usage += cost
}

func (c *localBillingCache) InvalidateAPIKeyRateLimit(ctx context.Context, keyID int64) error {
	c.rateMu.Lock()
	delete(c.rateLimits, keyID)
	c.rateMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.InvalidateAPIKeyRateLimit(ctx, keyID)
}

func (c *localBillingCache) GetUserPlatformQuotaCache(ctx context.Context, userID int64, platform string) (*service.UserPlatformQuotaCacheEntry, bool, error) {
	key := localQuotaKey{userID: userID, platform: platform}
	now := c.clock()
	c.quotaMu.Lock()
	if entry, ok := c.quotas[key]; ok {
		if entry.expires.After(now) {
			entry.accessed = c.nextAccess()
			c.quotas[key] = entry
			out := cloneUserPlatformQuotaCacheEntry(entry.value)
			c.quotaMu.Unlock()
			return out, true, nil
		}
		delete(c.quotas, key)
		delete(c.quotaDirty, key)
	}
	c.quotaMu.Unlock()

	if c.next == nil {
		return nil, false, nil
	}
	entry, ok, err := c.next.GetUserPlatformQuotaCache(ctx, userID, platform)
	if err != nil || !ok || entry == nil {
		return entry, ok, err
	}
	c.setQuotaLocal(key, entry, billingCacheTTL)
	return cloneUserPlatformQuotaCacheEntry(entry), true, nil
}

func (c *localBillingCache) SetUserPlatformQuotaCache(ctx context.Context, userID int64, platform string, entry *service.UserPlatformQuotaCacheEntry, ttl time.Duration) error {
	if entry != nil {
		c.setQuotaLocal(localQuotaKey{userID: userID, platform: platform}, entry, ttl)
	}
	if c.next == nil {
		return nil
	}
	return c.next.SetUserPlatformQuotaCache(ctx, userID, platform, entry, ttl)
}

func (c *localBillingCache) setQuotaLocal(key localQuotaKey, entry *service.UserPlatformQuotaCacheEntry, ttl time.Duration) {
	if entry == nil {
		return
	}
	now := c.clock()
	c.quotaMu.Lock()
	c.quotas[key] = localQuotaEntry{
		value:    cloneUserPlatformQuotaCacheEntry(entry),
		expires:  now.Add(localBillingTTL(ttl)),
		accessed: c.nextAccess(),
	}
	c.evictQuotasLocked(now)
	c.quotaMu.Unlock()
}

func (c *localBillingCache) DeleteUserPlatformQuotaCache(ctx context.Context, userID int64, platform string) error {
	key := localQuotaKey{userID: userID, platform: platform}
	c.quotaMu.Lock()
	delete(c.quotas, key)
	delete(c.quotaDirty, key)
	c.quotaMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.DeleteUserPlatformQuotaCache(ctx, userID, platform)
}

func (c *localBillingCache) IncrUserPlatformQuotaUsageCache(ctx context.Context, userID int64, platform string, cost float64, ttl time.Duration, markDirty bool) error {
	key := localQuotaKey{userID: userID, platform: platform}
	now := c.clock()
	c.quotaMu.Lock()
	if entry, ok := c.quotas[key]; ok && entry.value != nil && entry.value.SchemaVersion == service.UserPlatformQuotaCacheSchemaV1 {
		entry.value.DailyUsageUSD += cost
		entry.value.WeeklyUsageUSD += cost
		entry.value.MonthlyUsageUSD += cost
		entry.value.Version++
		entry.expires = now.Add(localBillingTTL(ttl))
		entry.accessed = c.nextAccess()
		c.quotas[key] = entry
		if markDirty {
			c.quotaDirty[key] = struct{}{}
		}
	}
	c.quotaMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.IncrUserPlatformQuotaUsageCache(ctx, userID, platform, cost, ttl, markDirty)
}

func (c *localBillingCache) PopDirtyUserPlatformQuotaKeys(ctx context.Context, n int) ([]service.UserPlatformQuotaKey, error) {
	if n <= 0 {
		return nil, nil
	}
	keys := make([]service.UserPlatformQuotaKey, 0, n)
	seen := make(map[localQuotaKey]struct{}, n)
	c.quotaMu.Lock()
	for key := range c.quotaDirty {
		delete(c.quotaDirty, key)
		seen[key] = struct{}{}
		keys = append(keys, service.UserPlatformQuotaKey{UserID: key.userID, Platform: key.platform})
		if len(keys) >= n {
			break
		}
	}
	c.quotaMu.Unlock()
	if len(keys) >= n || c.next == nil {
		return keys, nil
	}
	more, err := c.next.PopDirtyUserPlatformQuotaKeys(ctx, n-len(keys))
	if err != nil {
		if len(keys) > 0 {
			_ = c.ReaddDirtyUserPlatformQuotaKeys(context.Background(), keys)
		}
		return nil, err
	}
	for _, key := range more {
		localKey := localQuotaKey{userID: key.UserID, platform: key.Platform}
		if _, ok := seen[localKey]; ok {
			continue
		}
		seen[localKey] = struct{}{}
		keys = append(keys, key)
	}
	return keys, nil
}

func (c *localBillingCache) ReaddDirtyUserPlatformQuotaKeys(ctx context.Context, keys []service.UserPlatformQuotaKey) error {
	if len(keys) == 0 {
		return nil
	}
	c.quotaMu.Lock()
	for _, key := range keys {
		c.quotaDirty[localQuotaKey{userID: key.UserID, platform: key.Platform}] = struct{}{}
	}
	c.quotaMu.Unlock()
	if c.next == nil {
		return nil
	}
	return c.next.ReaddDirtyUserPlatformQuotaKeys(ctx, keys)
}

func (c *localBillingCache) BatchGetUserPlatformQuotaCache(ctx context.Context, keys []service.UserPlatformQuotaKey) ([]*service.UserPlatformQuotaCacheEntry, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	results := make([]*service.UserPlatformQuotaCacheEntry, len(keys))
	missIndex := make([]int, 0)
	missKeys := make([]service.UserPlatformQuotaKey, 0)
	now := c.clock()

	c.quotaMu.Lock()
	for i, key := range keys {
		localKey := localQuotaKey{userID: key.UserID, platform: key.Platform}
		entry, ok := c.quotas[localKey]
		if ok && entry.expires.After(now) {
			entry.accessed = c.nextAccess()
			c.quotas[localKey] = entry
			results[i] = cloneUserPlatformQuotaCacheEntry(entry.value)
			continue
		}
		if ok {
			delete(c.quotas, localKey)
			delete(c.quotaDirty, localKey)
		}
		missIndex = append(missIndex, i)
		missKeys = append(missKeys, key)
	}
	c.quotaMu.Unlock()

	if len(missKeys) == 0 || c.next == nil {
		return results, nil
	}
	missResults, err := c.next.BatchGetUserPlatformQuotaCache(ctx, missKeys)
	if err != nil {
		return nil, err
	}
	for i, entry := range missResults {
		if i >= len(missIndex) {
			break
		}
		if entry == nil {
			continue
		}
		target := missIndex[i]
		key := localQuotaKey{userID: keys[target].UserID, platform: keys[target].Platform}
		c.setQuotaLocal(key, entry, billingCacheTTL)
		results[target] = cloneUserPlatformQuotaCacheEntry(entry)
	}
	return results, nil
}

func cloneSubscriptionCacheData(in *service.SubscriptionCacheData) *service.SubscriptionCacheData {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneRateLimitCacheData(in *service.APIKeyRateLimitCacheData) *service.APIKeyRateLimitCacheData {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneUserPlatformQuotaCacheEntry(in *service.UserPlatformQuotaCacheEntry) *service.UserPlatformQuotaCacheEntry {
	if in == nil {
		return nil
	}
	out := *in
	out.DailyLimitUSD = cloneFloat64Ptr(in.DailyLimitUSD)
	out.WeeklyLimitUSD = cloneFloat64Ptr(in.WeeklyLimitUSD)
	out.MonthlyLimitUSD = cloneFloat64Ptr(in.MonthlyLimitUSD)
	out.DailyWindowStart = cloneTimePtr(in.DailyWindowStart)
	out.WeeklyWindowStart = cloneTimePtr(in.WeeklyWindowStart)
	out.MonthlyWindowStart = cloneTimePtr(in.MonthlyWindowStart)
	return &out
}

func cloneFloat64Ptr(in *float64) *float64 {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
