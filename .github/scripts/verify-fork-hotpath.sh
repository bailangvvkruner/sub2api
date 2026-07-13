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
require_fixed backend/internal/config/config.go 'viper.SetDefault("gateway.hotpath.local_billing_cache_write_through", false)' "local billing write-through must default off"
require_fixed backend/internal/config/config.go 'viper.SetDefault("gateway.hotpath.usage_billing_write_behind", true)' "usage billing write-behind must default on"
require_fixed backend/internal/config/config.go 'viper.SetDefault("gateway.hotpath.usage_billing_flush_interval_ms", 30000)' "usage billing write-behind interval must default to 30s"
require_fixed backend/internal/config/config.go 'viper.SetDefault("database.user_platform_quota_flusher_enabled", true)' "quota usage flusher must default on"
require_fixed backend/internal/config/config.go 'viper.SetDefault("database.user_platform_quota_flush_interval_ms", 30000)' "quota usage flusher interval must default to 30s"
require_fixed backend/internal/config/config.go 'fallback_selection_mode", "random"' "fork fallback selection default changed"

local_concurrency_file="backend/internal/repository/local_concurrency_cache.go"
local_billing_file="backend/internal/repository/local_billing_cache.go"
if [ -d backend/internal/hotpath ]; then
  local_concurrency_file="backend/internal/hotpath/concurrency_cache.go"
  local_billing_file="backend/internal/hotpath/billing_cache.go"
fi

require_file "$local_concurrency_file"
require_fixed "$local_concurrency_file" 'func NewLocalConcurrencyCache' "local concurrency cache constructor is missing"
require_fixed backend/internal/repository/wire.go 'if cfg.Gateway.HotPath.LocalConcurrencySlots {' "local concurrency cache is not config-gated"
if [ "$local_concurrency_file" = "backend/internal/hotpath/concurrency_cache.go" ]; then
  require_file backend/internal/repository/local_concurrency_cache.go
  require_fixed backend/internal/repository/local_concurrency_cache.go 'hotpath.NewLocalConcurrencyCache(' "local concurrency compatibility provider does not delegate to internal/hotpath"
  require_fixed backend/internal/repository/wire.go 'return NewLocalConcurrencyCache(' "local concurrency compatibility provider is not wired"
else
  require_fixed backend/internal/repository/wire.go 'return NewLocalConcurrencyCache(' "local concurrency cache is not wired"
fi

require_fixed backend/internal/service/deferred_service.go 'func NewDeferredServiceWithOptions' "deferred service options patch is missing"
require_fixed backend/internal/service/wire.go 'persistLastUsed = cfg.Gateway.HotPath.PersistAccountLastUsed' "last_used persistence switch is not wired"
require_regex backend/internal/repository/scheduler_cache.go 'func \(c \*schedulerCache\) UpdateLastUsed' "scheduler UpdateLastUsed hook is missing"
require_nearby_fixed backend/internal/repository/scheduler_cache.go 'func (c *schedulerCache) UpdateLastUsed' 'return nil' "scheduler UpdateLastUsed must stay disabled"
require_fixed backend/internal/repository/scheduler_cache.go 'account.LastUsedAt = nil' "scheduler cache rebuilds must scrub last_used"
require_regex backend/internal/service/scheduler_snapshot_service.go 'func \(s \*SchedulerSnapshotService\) handleLastUsedEvent' "scheduler snapshot last_used handler is missing"
require_nearby_fixed backend/internal/service/scheduler_snapshot_service.go 'func (s *SchedulerSnapshotService) handleLastUsedEvent' 'return nil' "scheduler snapshot last_used handler must stay disabled"

require_file "$local_billing_file"
require_fixed backend/internal/repository/billing_cache.go 'func ProvideBillingCache(rdb *redis.Client, cfg *config.Config) service.BillingCache {' "billing cache provider signature changed"
if [ "$local_billing_file" = "backend/internal/hotpath/billing_cache.go" ]; then
  require_file backend/internal/repository/local_billing_cache.go
  require_fixed backend/internal/repository/billing_cache.go 'return newLocalBillingCacheWithOptions(base, cfg.Gateway.HotPath.LocalBillingCacheMaxEntries, cfg.Gateway.HotPath.LocalBillingCacheWriteThrough)' "local billing cache compatibility provider is not wired"
  require_fixed backend/internal/repository/local_billing_cache.go 'hotpath.NewLocalBillingCacheWithOptions(next, maxEntries, writeThrough)' "local billing compatibility provider does not delegate to internal/hotpath"
  require_fixed "$local_billing_file" 'func NewLocalBillingCache(' "exported local billing cache constructor is missing"
  require_fixed "$local_billing_file" 'func NewLocalBillingCacheWithOptions(' "exported local billing cache write-through constructor is missing"
else
  require_fixed backend/internal/repository/billing_cache.go 'return newLocalBillingCacheWithOptions(base, cfg.Gateway.HotPath.LocalBillingCacheMaxEntries, cfg.Gateway.HotPath.LocalBillingCacheWriteThrough)' "local billing cache wrapper is not wired"
  require_fixed "$local_billing_file" 'func newLocalBillingCache(next service.BillingCache, maxEntries int) service.BillingCache' "local billing cache constructor is missing"
  require_fixed "$local_billing_file" 'func newLocalBillingCacheWithOptions(next service.BillingCache, maxEntries int, writeThrough bool) service.BillingCache' "local billing cache write-through option is missing"
fi
require_fixed "$local_billing_file" 'GetUserBalance' "local billing cache does not cover balance reads"
require_fixed "$local_billing_file" 'DeductUserBalance' "local billing cache does not cover balance deductions"
require_fixed "$local_billing_file" 'GetAPIKeyRateLimit' "local billing cache does not cover API key rate limit reads"
require_fixed "$local_billing_file" 'IncrUserPlatformQuotaUsageCache' "local billing cache does not cover quota usage increments"
require_fixed "$local_billing_file" 'PopDirtyUserPlatformQuotaKeys' "local billing cache dirty queue pop is missing"
require_fixed "$local_billing_file" 'AcknowledgeUserPlatformQuotaFlush' "local billing cache in-flight flush ACK is missing"
require_fixed "$local_billing_file" 'BatchGetUserPlatformQuotaCache' "local billing cache batch quota read is missing"

require_file backend/internal/service/user_platform_quota_flusher.go
require_fixed backend/internal/service/user_platform_quota_flusher.go 'type UserPlatformQuotaUsageFlusher struct' "quota usage flusher type is missing"
require_fixed backend/internal/service/user_platform_quota_flusher.go 's.acknowledge(keys)' "quota flusher does not release in-flight protection on terminal outcomes"
require_fixed backend/internal/service/wire.go 'ProvideUserPlatformQuotaUsageFlusher,' "quota usage flusher is not in the provider set"
require_fixed backend/internal/service/wire.go 'func ProvideUserPlatformQuotaUsageFlusher(' "quota usage flusher provider is missing"
require_fixed backend/internal/service/billing_cache_service.go 'markDirty := s.cfg != nil && s.cfg.Database.UserPlatformQuotaFlusherEnabled' "quota dirty marking is not config-gated"
require_file backend/internal/service/usage_billing_write_behind.go
require_fixed backend/internal/service/usage_billing_write_behind.go 'type UsageBillingWriteBehind struct' "usage billing write-behind type is missing"
require_fixed backend/internal/service/usage_billing_write_behind.go 'func (s *UsageBillingWriteBehind) Apply' "usage billing write-behind apply path is missing"
require_fixed backend/internal/service/usage_billing_write_behind.go 'func (s *UsageBillingWriteBehind) Flush' "usage billing write-behind flush path is missing"
require_fixed backend/internal/service/api_key_service.go 'func (s *APIKeyService) UsageBillingWriteBehind() *UsageBillingWriteBehind' "API key service no longer exposes the write-behind worker"
require_fixed backend/internal/service/gateway_usage_billing.go 'usageBillingWriteBehind = provider.UsageBillingWriteBehind()' "gateway billing no longer resolves write-behind from APIKeyService"
require_fixed backend/internal/service/gateway_usage_billing.go 'usageBillingWriteBehind.Apply' "gateway billing does not use write-behind"
require_fixed backend/internal/service/wire.go 'ProvideUsageBillingWriteBehind,' "usage billing write-behind is not in the provider set"

require_file backend/internal/repository/usage_log_pending_repo.go
require_fixed backend/internal/repository/usage_log_pending_repo.go 'defaultUsageLogPendingFlushInterval = 30 * time.Second' "usage logs no longer default to a 30s pending flush"
require_fixed backend/internal/repository/usage_log_repo.go 'return NewUsageLogRepositoryWithPending(base, rdb, cfg)' "usage log repository no longer enables the pending wrapper"

require_fixed backend/internal/service/admin_user.go 'ApplyUserBalanceDeltaRealtime' "admin balance changes no longer refresh L1/Redis in real time"
require_fixed backend/internal/service/admin_group.go 'RefreshSubscription' "admin group changes no longer refresh subscription caches"
require_fixed backend/internal/service/subscription_service.go 'func (s *SubscriptionService) refreshSubscriptionCaches' "subscription realtime refresh helper is missing"
require_fixed backend/internal/service/subscription_service.go 's.billingCacheService.RefreshSubscription' "subscription changes no longer refresh billing caches"
require_fixed backend/internal/service/gateway_scheduling.go 'func sortAccountsByPriorityAndLoad' "gateway scheduling reverted to LastUsedAt ordering"
require_fixed backend/internal/service/gateway_scheduling.go 'func sortAccountsByPriorityOnlyRandom' "gateway random fallback helper is missing"
require_fixed backend/internal/service/openai_gateway_scheduling.go 'sortAccountsByPriorityOnlyRandom(candidates, false)' "OpenAI fallback scheduling reverted to LastUsedAt ordering"
require_fixed backend/internal/server/middleware/api_key_auth.go 'apiKeyService.IsQuotaExhausted(apiKey)' "main auth middleware no longer checks the write-behind quota shadow"
require_fixed backend/internal/server/middleware/api_key_auth_google.go 'apiKeyService.IsQuotaExhausted(apiKey)' "Google auth middleware no longer checks the write-behind quota shadow"

require_fixed README.md 'gateway.hotpath.local_billing_cache: true' "README no longer documents local billing L1 cache"
require_fixed README.md 'gateway.hotpath.usage_billing_write_behind: true' "README no longer documents usage billing write-behind"
require_fixed deploy/config.example.yaml 'local_billing_cache: true' "deploy example lost local billing cache switch"
require_fixed deploy/config.example.yaml 'local_billing_cache_max_entries: 262144' "deploy example lost local billing cache size"
require_fixed deploy/config.example.yaml 'local_billing_cache_write_through: false' "deploy example lost local billing write-through switch"
require_fixed deploy/config.example.yaml 'usage_billing_write_behind: true' "deploy example lost usage billing write-behind switch"
require_fixed deploy/config.example.yaml 'usage_billing_flush_interval_ms: 30000' "deploy example lost usage billing write-behind 30s interval"
require_fixed deploy/config.example.yaml 'user_platform_quota_flusher_enabled: true' "deploy example lost quota flusher switch"
require_fixed deploy/config.example.yaml 'user_platform_quota_flush_interval_ms: 30000' "deploy example lost quota flusher 30s interval"
