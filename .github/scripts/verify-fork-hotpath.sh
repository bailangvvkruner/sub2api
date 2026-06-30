#!/usr/bin/env bash
set -euo pipefail

require_file() {
  if [ ! -f "$1" ]; then
    echo "::error file=$1::Required fork patch file is missing"
    exit 1
  fi
}

require_fixed() {
  local file="$1"
  local needle="$2"
  local message="$3"
  if ! grep -Fq "$needle" "$file"; then
    echo "::error file=$file::$message"
    exit 1
  fi
}

require_regex() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if ! grep -Eq "$pattern" "$file"; then
    echo "::error file=$file::$message"
    exit 1
  fi
}

require_nearby_fixed() {
  local file="$1"
  local anchor="$2"
  local needle="$3"
  local message="$4"
  if ! grep -F -A2 "$anchor" "$file" | grep -Fq "$needle"; then
    echo "::error file=$file::$message"
    exit 1
  fi
}

# Keep the fork hot path intentionally L1-first: process cache > Redis > DB.
require_fixed backend/internal/config/config.go 'viper.SetDefault("gateway.hotpath.local_concurrency_slots", true)' "local concurrency slots must default to process memory"
require_fixed backend/internal/config/config.go 'viper.SetDefault("gateway.hotpath.persist_account_last_used", false)' "account last_used writes must default off"
require_fixed backend/internal/config/config.go 'viper.SetDefault("gateway.hotpath.local_billing_cache", true)' "local billing L1 cache must default on"
require_fixed backend/internal/config/config.go 'viper.SetDefault("gateway.hotpath.local_billing_cache_max_entries", 262144)' "local billing L1 cache size default changed"
require_fixed backend/internal/config/config.go 'viper.SetDefault("database.user_platform_quota_flusher_enabled", true)' "quota usage flusher must default on"
require_fixed backend/internal/config/config.go 'viper.SetDefault("database.user_platform_quota_flush_interval_ms", 30000)' "quota usage flusher interval must default to 30s"
require_fixed backend/internal/config/config.go 'fallback_selection_mode", "random"' "fork fallback selection default changed"

require_file backend/internal/repository/local_concurrency_cache.go
require_fixed backend/internal/repository/local_concurrency_cache.go 'func NewLocalConcurrencyCache' "local concurrency cache constructor is missing"
require_fixed backend/internal/repository/wire.go 'if cfg.Gateway.HotPath.LocalConcurrencySlots {' "local concurrency cache is not config-gated"
require_fixed backend/internal/repository/wire.go 'return NewLocalConcurrencyCache(' "local concurrency cache is not wired"

require_fixed backend/internal/service/deferred_service.go 'func NewDeferredServiceWithOptions' "deferred service options patch is missing"
require_fixed backend/internal/service/wire.go 'persistLastUsed = cfg.Gateway.HotPath.PersistAccountLastUsed' "last_used persistence switch is not wired"
require_regex backend/internal/repository/scheduler_cache.go 'func \(c \*schedulerCache\) UpdateLastUsed' "scheduler UpdateLastUsed hook is missing"
require_nearby_fixed backend/internal/repository/scheduler_cache.go 'func (c *schedulerCache) UpdateLastUsed' 'return nil' "scheduler UpdateLastUsed must stay disabled"
require_regex backend/internal/service/scheduler_snapshot_service.go 'func \(s \*SchedulerSnapshotService\) handleLastUsedEvent' "scheduler snapshot last_used handler is missing"
require_nearby_fixed backend/internal/service/scheduler_snapshot_service.go 'func (s *SchedulerSnapshotService) handleLastUsedEvent' 'return nil' "scheduler snapshot last_used handler must stay disabled"

require_file backend/internal/repository/local_billing_cache.go
require_fixed backend/internal/repository/billing_cache.go 'func ProvideBillingCache(rdb *redis.Client, cfg *config.Config) service.BillingCache {' "billing cache provider signature changed"
require_fixed backend/internal/repository/billing_cache.go 'return newLocalBillingCache(base, cfg.Gateway.HotPath.LocalBillingCacheMaxEntries)' "local billing cache wrapper is not wired"
require_fixed backend/internal/repository/local_billing_cache.go 'func newLocalBillingCache(next service.BillingCache, maxEntries int) service.BillingCache' "local billing cache constructor is missing"
require_fixed backend/internal/repository/local_billing_cache.go 'func (c *localBillingCache) GetUserBalance' "local billing cache does not cover balance reads"
require_fixed backend/internal/repository/local_billing_cache.go 'func (c *localBillingCache) DeductUserBalance' "local billing cache does not cover balance deductions"
require_fixed backend/internal/repository/local_billing_cache.go 'func (c *localBillingCache) GetAPIKeyRateLimit' "local billing cache does not cover API key rate limit reads"
require_fixed backend/internal/repository/local_billing_cache.go 'func (c *localBillingCache) IncrUserPlatformQuotaUsageCache' "local billing cache does not cover quota usage increments"
require_fixed backend/internal/repository/local_billing_cache.go 'func (c *localBillingCache) PopDirtyUserPlatformQuotaKeys' "local billing cache dirty queue pop is missing"
require_fixed backend/internal/repository/local_billing_cache.go 'func (c *localBillingCache) BatchGetUserPlatformQuotaCache' "local billing cache batch quota read is missing"

require_file backend/internal/service/user_platform_quota_flusher.go
require_fixed backend/internal/service/user_platform_quota_flusher.go 'type UserPlatformQuotaUsageFlusher struct' "quota usage flusher type is missing"
require_fixed backend/internal/service/wire.go 'ProvideUserPlatformQuotaUsageFlusher,' "quota usage flusher is not in the provider set"
require_fixed backend/internal/service/wire.go 'func ProvideUserPlatformQuotaUsageFlusher(' "quota usage flusher provider is missing"
require_fixed backend/internal/service/billing_cache_service.go 'markDirty := s.cfg.Database.UserPlatformQuotaFlusherEnabled' "quota dirty marking is not config-gated"

require_fixed README.md 'gateway.hotpath.local_billing_cache: true' "README no longer documents local billing L1 cache"
require_fixed deploy/config.example.yaml 'local_billing_cache: true' "deploy example lost local billing cache switch"
require_fixed deploy/config.example.yaml 'local_billing_cache_max_entries: 262144' "deploy example lost local billing cache size"
require_fixed deploy/config.example.yaml 'user_platform_quota_flusher_enabled: true' "deploy example lost quota flusher switch"
require_fixed deploy/config.example.yaml 'user_platform_quota_flush_interval_ms: 30000' "deploy example lost quota flusher 30s interval"
