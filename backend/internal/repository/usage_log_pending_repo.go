package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

const (
	defaultUsageLogPendingFlushInterval = 30 * time.Second
	usageLogPendingRedisTimeout         = 250 * time.Millisecond
	usageLogPendingL2TTL                = 24 * time.Hour
	usageLogPendingMaxDrain             = 4096
)

type usageLogPendingRepository struct {
	next     service.UsageLogRepository
	rdb      *redis.Client
	l2Key    string
	interval time.Duration

	mu      sync.Mutex
	pending []*service.UsageLog

	stopCh  chan struct{}
	started atomic.Bool
	stopped atomic.Bool
	wg      sync.WaitGroup

	enqueuedTotal       atomic.Uint64
	flushedTotal        atomic.Uint64
	flushErrorTotal     atomic.Uint64
	l2PendingEntries    atomic.Int64
	l2MirrorErrorTotal  atomic.Uint64
	l2TrimErrorTotal    atomic.Uint64
	droppedAfterStopped atomic.Uint64
}

type usageLogPendingRecord struct {
	UserID                int64               `json:"user_id"`
	APIKeyID              int64               `json:"api_key_id"`
	AccountID             int64               `json:"account_id"`
	RequestID             string              `json:"request_id,omitempty"`
	Model                 string              `json:"model,omitempty"`
	RequestedModel        string              `json:"requested_model,omitempty"`
	UpstreamModel         *string             `json:"upstream_model,omitempty"`
	ChannelID             *int64              `json:"channel_id,omitempty"`
	ModelMappingChain     *string             `json:"model_mapping_chain,omitempty"`
	BillingTier           *string             `json:"billing_tier,omitempty"`
	BillingMode           *string             `json:"billing_mode,omitempty"`
	ServiceTier           *string             `json:"service_tier,omitempty"`
	ReasoningEffort       *string             `json:"reasoning_effort,omitempty"`
	InboundEndpoint       *string             `json:"inbound_endpoint,omitempty"`
	UpstreamEndpoint      *string             `json:"upstream_endpoint,omitempty"`
	GroupID               *int64              `json:"group_id,omitempty"`
	SubscriptionID        *int64              `json:"subscription_id,omitempty"`
	InputTokens           int                 `json:"input_tokens"`
	OutputTokens          int                 `json:"output_tokens"`
	CacheCreationTokens   int                 `json:"cache_creation_tokens"`
	CacheReadTokens       int                 `json:"cache_read_tokens"`
	CacheCreation5mTokens int                 `json:"cache_creation_5m_tokens"`
	CacheCreation1hTokens int                 `json:"cache_creation_1h_tokens"`
	ImageOutputTokens     int                 `json:"image_output_tokens"`
	ImageOutputCost       float64             `json:"image_output_cost,omitempty"`
	InputCost             float64             `json:"input_cost,omitempty"`
	OutputCost            float64             `json:"output_cost,omitempty"`
	CacheCreationCost     float64             `json:"cache_creation_cost,omitempty"`
	CacheReadCost         float64             `json:"cache_read_cost,omitempty"`
	TotalCost             float64             `json:"total_cost,omitempty"`
	ActualCost            float64             `json:"actual_cost,omitempty"`
	RateMultiplier        float64             `json:"rate_multiplier,omitempty"`
	AccountRateMultiplier *float64            `json:"account_rate_multiplier,omitempty"`
	AccountStatsCost      *float64            `json:"account_stats_cost,omitempty"`
	BillingType           int8                `json:"billing_type"`
	RequestType           service.RequestType `json:"request_type"`
	Stream                bool                `json:"stream"`
	OpenAIWSMode          bool                `json:"openai_ws_mode"`
	DurationMs            *int                `json:"duration_ms,omitempty"`
	FirstTokenMs          *int                `json:"first_token_ms,omitempty"`
	UserAgent             *string             `json:"user_agent,omitempty"`
	IPAddress             *string             `json:"ip_address,omitempty"`
	CacheTTLOverridden    bool                `json:"cache_ttl_overridden"`
	ImageCount            int                 `json:"image_count"`
	ImageSize             *string             `json:"image_size,omitempty"`
	ImageInputSize        *string             `json:"image_input_size,omitempty"`
	ImageOutputSize       *string             `json:"image_output_size,omitempty"`
	ImageSizeSource       *string             `json:"image_size_source,omitempty"`
	ImageSizeBreakdown    map[string]int      `json:"image_size_breakdown,omitempty"`
	MediaType             *string             `json:"media_type,omitempty"`
	CreatedAtUnixNano     int64               `json:"created_at_unix_nano"`
}

func NewUsageLogRepositoryWithPending(base service.UsageLogRepository, rdb *redis.Client, cfg *config.Config) service.UsageLogRepository {
	if base == nil {
		return nil
	}
	interval := defaultUsageLogPendingFlushInterval
	if cfg != nil && cfg.Gateway.HotPath.UsageBillingFlushIntervalMs > 0 {
		interval = time.Duration(cfg.Gateway.HotPath.UsageBillingFlushIntervalMs) * time.Millisecond
	}
	repo := &usageLogPendingRepository{
		next:     base,
		rdb:      rdb,
		l2Key:    usageLogPendingInstanceKey(),
		interval: interval,
		stopCh:   make(chan struct{}),
		pending:  make([]*service.UsageLog, 0),
	}
	repo.Start()
	return repo
}

func (r *usageLogPendingRepository) Start() {
	if r == nil || !r.started.CompareAndSwap(false, true) {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.Flush(context.Background())
			case <-r.stopCh:
				return
			}
		}
	}()
	logger.LegacyPrintf("repository.usage_log_pending", "[UsageLogPending] started interval=%s", r.interval)
}

func (r *usageLogPendingRepository) Stop() {
	if r == nil {
		return
	}
	if r.stopped.CompareAndSwap(false, true) {
		close(r.stopCh)
	}
	r.wg.Wait()
	r.Flush(context.Background())
}

func (r *usageLogPendingRepository) Stats() service.UsageLogPendingStats {
	if r == nil {
		return service.UsageLogPendingStats{}
	}
	r.mu.Lock()
	pending := len(r.pending)
	r.mu.Unlock()
	return service.UsageLogPendingStats{
		PendingL1Entries:    pending,
		PendingL2Entries:    r.l2PendingEntries.Load(),
		EnqueuedTotal:       r.enqueuedTotal.Load(),
		FlushedTotal:        r.flushedTotal.Load(),
		FlushErrorTotal:     r.flushErrorTotal.Load(),
		L2MirrorErrorTotal:  r.l2MirrorErrorTotal.Load(),
		L2TrimErrorTotal:    r.l2TrimErrorTotal.Load(),
		DroppedAfterStopped: r.droppedAfterStopped.Load(),
	}
}

func (r *usageLogPendingRepository) Create(ctx context.Context, log *service.UsageLog) (bool, error) {
	return r.next.Create(ctx, log)
}

func (r *usageLogPendingRepository) CreateBestEffort(ctx context.Context, log *service.UsageLog) error {
	if log == nil {
		return nil
	}
	if r.stopped.Load() {
		r.droppedAfterStopped.Add(1)
		if writer, ok := r.next.(interface {
			CreateBestEffort(context.Context, *service.UsageLog) error
		}); ok {
			return writer.CreateBestEffort(ctx, log)
		}
		_, err := r.next.Create(ctx, log)
		return err
	}
	cloned := cloneUsageLog(log)
	r.mu.Lock()
	r.pending = append(r.pending, cloned)
	r.mu.Unlock()
	r.enqueuedTotal.Add(1)
	if err := r.mirrorPendingToL2(ctx, cloned); err != nil {
		r.l2MirrorErrorTotal.Add(1)
		logger.LegacyPrintf("repository.usage_log_pending", "[UsageLogPending] L2 mirror failed, continuing L1-only: %v", err)
	}
	return nil
}

func (r *usageLogPendingRepository) Flush(ctx context.Context) {
	if r == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		batch := r.takeBatch(usageLogPendingMaxDrain)
		if len(batch) == 0 {
			return
		}
		if err := r.flushBatch(ctx, batch); err != nil {
			r.requeue(batch)
			r.flushErrorTotal.Add(1)
			logger.LegacyPrintf("repository.usage_log_pending", "[UsageLogPending] ALERT flush failed: %v", err)
			return
		}
		r.flushedTotal.Add(uint64(len(batch)))
		if err := r.trimPendingL2(ctx, int64(len(batch))); err != nil {
			r.l2TrimErrorTotal.Add(1)
			logger.LegacyPrintf("repository.usage_log_pending", "[UsageLogPending] L2 trim failed after DB flush: %v", err)
		}
		if len(batch) < usageLogPendingMaxDrain {
			return
		}
	}
}

func (r *usageLogPendingRepository) takeBatch(limit int) []*service.UsageLog {
	if limit <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return nil
	}
	if len(r.pending) <= limit {
		batch := r.pending
		r.pending = make([]*service.UsageLog, 0)
		return batch
	}
	batch := append([]*service.UsageLog(nil), r.pending[:limit]...)
	remaining := append([]*service.UsageLog(nil), r.pending[limit:]...)
	r.pending = remaining
	return batch
}

func (r *usageLogPendingRepository) requeue(batch []*service.UsageLog) {
	if len(batch) == 0 {
		return
	}
	r.mu.Lock()
	r.pending = append(batch, r.pending...)
	r.mu.Unlock()
}

func (r *usageLogPendingRepository) flushBatch(ctx context.Context, batch []*service.UsageLog) error {
	if len(batch) == 0 {
		return nil
	}
	writer, hasBestEffort := r.next.(interface {
		CreateBestEffort(context.Context, *service.UsageLog) error
	})
	for _, log := range batch {
		if log == nil {
			continue
		}
		if hasBestEffort {
			if err := writer.CreateBestEffort(ctx, log); err != nil {
				return err
			}
			continue
		}
		if _, err := r.next.Create(ctx, log); err != nil {
			return err
		}
	}
	return nil
}

func (r *usageLogPendingRepository) mirrorPendingToL2(ctx context.Context, log *service.UsageLog) error {
	if r == nil || r.rdb == nil || log == nil {
		return nil
	}
	payload, err := json.Marshal(usageLogToPendingRecord(log))
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	mirrorCtx, cancel := context.WithTimeout(ctx, usageLogPendingRedisTimeout)
	defer cancel()
	pipe := r.rdb.Pipeline()
	pipe.RPush(mirrorCtx, r.l2Key, payload)
	pipe.Expire(mirrorCtx, r.l2Key, usageLogPendingL2TTL)
	if _, err := pipe.Exec(mirrorCtx); err != nil {
		return err
	}
	r.l2PendingEntries.Add(1)
	return nil
}

func (r *usageLogPendingRepository) trimPendingL2(ctx context.Context, n int64) error {
	if r == nil || r.rdb == nil || n <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	trimCtx, cancel := context.WithTimeout(ctx, usageLogPendingRedisTimeout)
	defer cancel()
	if err := r.rdb.LTrim(trimCtx, r.l2Key, n, -1).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	for {
		current := r.l2PendingEntries.Load()
		next := current - n
		if next < 0 {
			next = 0
		}
		if r.l2PendingEntries.CompareAndSwap(current, next) {
			return nil
		}
	}
}

func usageLogToPendingRecord(log *service.UsageLog) usageLogPendingRecord {
	createdAt := log.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	return usageLogPendingRecord{
		UserID:                log.UserID,
		APIKeyID:              log.APIKeyID,
		AccountID:             log.AccountID,
		RequestID:             log.RequestID,
		Model:                 log.Model,
		RequestedModel:        log.RequestedModel,
		UpstreamModel:         cloneStringPtr(log.UpstreamModel),
		ChannelID:             cloneInt64Ptr(log.ChannelID),
		ModelMappingChain:     cloneStringPtr(log.ModelMappingChain),
		BillingTier:           cloneStringPtr(log.BillingTier),
		BillingMode:           cloneStringPtr(log.BillingMode),
		ServiceTier:           cloneStringPtr(log.ServiceTier),
		ReasoningEffort:       cloneStringPtr(log.ReasoningEffort),
		InboundEndpoint:       cloneStringPtr(log.InboundEndpoint),
		UpstreamEndpoint:      cloneStringPtr(log.UpstreamEndpoint),
		GroupID:               cloneInt64Ptr(log.GroupID),
		SubscriptionID:        cloneInt64Ptr(log.SubscriptionID),
		InputTokens:           log.InputTokens,
		OutputTokens:          log.OutputTokens,
		CacheCreationTokens:   log.CacheCreationTokens,
		CacheReadTokens:       log.CacheReadTokens,
		CacheCreation5mTokens: log.CacheCreation5mTokens,
		CacheCreation1hTokens: log.CacheCreation1hTokens,
		ImageOutputTokens:     log.ImageOutputTokens,
		ImageOutputCost:       log.ImageOutputCost,
		InputCost:             log.InputCost,
		OutputCost:            log.OutputCost,
		CacheCreationCost:     log.CacheCreationCost,
		CacheReadCost:         log.CacheReadCost,
		TotalCost:             log.TotalCost,
		ActualCost:            log.ActualCost,
		RateMultiplier:        log.RateMultiplier,
		AccountRateMultiplier: cloneFloat64Ptr(log.AccountRateMultiplier),
		AccountStatsCost:      cloneFloat64Ptr(log.AccountStatsCost),
		BillingType:           log.BillingType,
		RequestType:           log.RequestType,
		Stream:                log.Stream,
		OpenAIWSMode:          log.OpenAIWSMode,
		DurationMs:            cloneIntPtr(log.DurationMs),
		FirstTokenMs:          cloneIntPtr(log.FirstTokenMs),
		UserAgent:             cloneStringPtr(log.UserAgent),
		IPAddress:             cloneStringPtr(log.IPAddress),
		CacheTTLOverridden:    log.CacheTTLOverridden,
		ImageCount:            log.ImageCount,
		ImageSize:             cloneStringPtr(log.ImageSize),
		ImageInputSize:        cloneStringPtr(log.ImageInputSize),
		ImageOutputSize:       cloneStringPtr(log.ImageOutputSize),
		ImageSizeSource:       cloneStringPtr(log.ImageSizeSource),
		ImageSizeBreakdown:    cloneStringIntMap(log.ImageSizeBreakdown),
		MediaType:             cloneStringPtr(log.MediaType),
		CreatedAtUnixNano:     createdAt.UnixNano(),
	}
}

func usageLogPendingInstanceKey() string {
	host, _ := os.Hostname()
	host = strings.TrimSpace(host)
	if host == "" {
		host = "unknown"
	}
	return "usage:pending:log:" + host + ":" + strconv.Itoa(os.Getpid())
}

func cloneUsageLog(in *service.UsageLog) *service.UsageLog {
	if in == nil {
		return nil
	}
	out := *in
	out.UpstreamModel = cloneStringPtr(in.UpstreamModel)
	out.ChannelID = cloneInt64Ptr(in.ChannelID)
	out.ModelMappingChain = cloneStringPtr(in.ModelMappingChain)
	out.BillingTier = cloneStringPtr(in.BillingTier)
	out.BillingMode = cloneStringPtr(in.BillingMode)
	out.ServiceTier = cloneStringPtr(in.ServiceTier)
	out.ReasoningEffort = cloneStringPtr(in.ReasoningEffort)
	out.InboundEndpoint = cloneStringPtr(in.InboundEndpoint)
	out.UpstreamEndpoint = cloneStringPtr(in.UpstreamEndpoint)
	out.GroupID = cloneInt64Ptr(in.GroupID)
	out.SubscriptionID = cloneInt64Ptr(in.SubscriptionID)
	out.AccountRateMultiplier = cloneFloat64Ptr(in.AccountRateMultiplier)
	out.AccountStatsCost = cloneFloat64Ptr(in.AccountStatsCost)
	out.DurationMs = cloneIntPtr(in.DurationMs)
	out.FirstTokenMs = cloneIntPtr(in.FirstTokenMs)
	out.UserAgent = cloneStringPtr(in.UserAgent)
	out.IPAddress = cloneStringPtr(in.IPAddress)
	out.ImageSize = cloneStringPtr(in.ImageSize)
	out.ImageInputSize = cloneStringPtr(in.ImageInputSize)
	out.ImageOutputSize = cloneStringPtr(in.ImageOutputSize)
	out.ImageSizeSource = cloneStringPtr(in.ImageSizeSource)
	out.ImageSizeBreakdown = cloneStringIntMap(in.ImageSizeBreakdown)
	out.MediaType = cloneStringPtr(in.MediaType)
	out.User = nil
	out.APIKey = nil
	out.Account = nil
	out.Group = nil
	out.Subscription = nil
	return &out
}

func cloneStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneIntPtr(in *int) *int {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneInt64Ptr(in *int64) *int64 {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneStringIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (r *usageLogPendingRepository) GetByID(ctx context.Context, id int64) (*service.UsageLog, error) {
	return r.next.GetByID(ctx, id)
}

func (r *usageLogPendingRepository) Delete(ctx context.Context, id int64) error {
	return r.next.Delete(ctx, id)
}

func (r *usageLogPendingRepository) ListByUser(ctx context.Context, userID int64, params pagination.PaginationParams) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return r.next.ListByUser(ctx, userID, params)
}

func (r *usageLogPendingRepository) ListByAPIKey(ctx context.Context, apiKeyID int64, params pagination.PaginationParams) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return r.next.ListByAPIKey(ctx, apiKeyID, params)
}

func (r *usageLogPendingRepository) ListByAccount(ctx context.Context, accountID int64, params pagination.PaginationParams) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return r.next.ListByAccount(ctx, accountID, params)
}

func (r *usageLogPendingRepository) ListByUserAndTimeRange(ctx context.Context, userID int64, startTime, endTime time.Time) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return r.next.ListByUserAndTimeRange(ctx, userID, startTime, endTime)
}

func (r *usageLogPendingRepository) ListByAPIKeyAndTimeRange(ctx context.Context, apiKeyID int64, startTime, endTime time.Time) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return r.next.ListByAPIKeyAndTimeRange(ctx, apiKeyID, startTime, endTime)
}

func (r *usageLogPendingRepository) ListByAccountAndTimeRange(ctx context.Context, accountID int64, startTime, endTime time.Time) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return r.next.ListByAccountAndTimeRange(ctx, accountID, startTime, endTime)
}

func (r *usageLogPendingRepository) ListByModelAndTimeRange(ctx context.Context, modelName string, startTime, endTime time.Time) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return r.next.ListByModelAndTimeRange(ctx, modelName, startTime, endTime)
}

func (r *usageLogPendingRepository) GetAccountWindowStats(ctx context.Context, accountID int64, startTime time.Time) (*usagestats.AccountStats, error) {
	return r.next.GetAccountWindowStats(ctx, accountID, startTime)
}

func (r *usageLogPendingRepository) GetAccountWindowStatsBatch(ctx context.Context, accountIDs []int64, startTime time.Time) (map[int64]*usagestats.AccountStats, error) {
	if batchReader, ok := r.next.(interface {
		GetAccountWindowStatsBatch(context.Context, []int64, time.Time) (map[int64]*usagestats.AccountStats, error)
	}); ok {
		return batchReader.GetAccountWindowStatsBatch(ctx, accountIDs, startTime)
	}
	result := make(map[int64]*usagestats.AccountStats, len(accountIDs))
	for _, accountID := range accountIDs {
		stats, err := r.next.GetAccountWindowStats(ctx, accountID, startTime)
		if err != nil {
			return nil, err
		}
		result[accountID] = stats
	}
	return result, nil
}

func (r *usageLogPendingRepository) GetAccountTodayStats(ctx context.Context, accountID int64) (*usagestats.AccountStats, error) {
	return r.next.GetAccountTodayStats(ctx, accountID)
}

func (r *usageLogPendingRepository) GetDashboardStats(ctx context.Context) (*usagestats.DashboardStats, error) {
	return r.next.GetDashboardStats(ctx)
}

func (r *usageLogPendingRepository) GetUsageTrendWithFilters(ctx context.Context, startTime, endTime time.Time, granularity string, userID, apiKeyID, accountID, groupID int64, model string, requestType *int16, stream *bool, billingType *int8) ([]usagestats.TrendDataPoint, error) {
	return r.next.GetUsageTrendWithFilters(ctx, startTime, endTime, granularity, userID, apiKeyID, accountID, groupID, model, requestType, stream, billingType)
}

func (r *usageLogPendingRepository) GetUsageTrendWithUsageFilters(ctx context.Context, startTime, endTime time.Time, granularity string, filters usagestats.UsageLogFilters) ([]usagestats.TrendDataPoint, error) {
	if filterRepo, ok := r.next.(interface {
		GetUsageTrendWithUsageFilters(context.Context, time.Time, time.Time, string, usagestats.UsageLogFilters) ([]usagestats.TrendDataPoint, error)
	}); ok {
		return filterRepo.GetUsageTrendWithUsageFilters(ctx, startTime, endTime, granularity, filters)
	}
	return r.next.GetUsageTrendWithFilters(ctx, startTime, endTime, granularity, filters.UserID, filters.APIKeyID, filters.AccountID, filters.GroupID, filters.Model, filters.RequestType, filters.Stream, filters.BillingType)
}

func (r *usageLogPendingRepository) GetModelStatsWithFilters(ctx context.Context, startTime, endTime time.Time, userID, apiKeyID, accountID, groupID int64, requestType *int16, stream *bool, billingType *int8) ([]usagestats.ModelStat, error) {
	return r.next.GetModelStatsWithFilters(ctx, startTime, endTime, userID, apiKeyID, accountID, groupID, requestType, stream, billingType)
}

func (r *usageLogPendingRepository) GetModelStatsWithFiltersBySource(ctx context.Context, startTime, endTime time.Time, userID, apiKeyID, accountID, groupID int64, requestType *int16, stream *bool, billingType *int8, source string) ([]usagestats.ModelStat, error) {
	if sourceRepo, ok := r.next.(interface {
		GetModelStatsWithFiltersBySource(context.Context, time.Time, time.Time, int64, int64, int64, int64, *int16, *bool, *int8, string) ([]usagestats.ModelStat, error)
	}); ok {
		return sourceRepo.GetModelStatsWithFiltersBySource(ctx, startTime, endTime, userID, apiKeyID, accountID, groupID, requestType, stream, billingType, source)
	}
	return r.next.GetModelStatsWithFilters(ctx, startTime, endTime, userID, apiKeyID, accountID, groupID, requestType, stream, billingType)
}

func (r *usageLogPendingRepository) GetModelStatsWithUsageFiltersBySource(ctx context.Context, startTime, endTime time.Time, filters usagestats.UsageLogFilters, source string) ([]usagestats.ModelStat, error) {
	if filterRepo, ok := r.next.(interface {
		GetModelStatsWithUsageFiltersBySource(context.Context, time.Time, time.Time, usagestats.UsageLogFilters, string) ([]usagestats.ModelStat, error)
	}); ok {
		return filterRepo.GetModelStatsWithUsageFiltersBySource(ctx, startTime, endTime, filters, source)
	}
	return r.GetModelStatsWithFiltersBySource(ctx, startTime, endTime, filters.UserID, filters.APIKeyID, filters.AccountID, filters.GroupID, filters.RequestType, filters.Stream, filters.BillingType, source)
}

func (r *usageLogPendingRepository) GetEndpointStatsWithFilters(ctx context.Context, startTime, endTime time.Time, userID, apiKeyID, accountID, groupID int64, model string, requestType *int16, stream *bool, billingType *int8) ([]usagestats.EndpointStat, error) {
	return r.next.GetEndpointStatsWithFilters(ctx, startTime, endTime, userID, apiKeyID, accountID, groupID, model, requestType, stream, billingType)
}

func (r *usageLogPendingRepository) GetUpstreamEndpointStatsWithFilters(ctx context.Context, startTime, endTime time.Time, userID, apiKeyID, accountID, groupID int64, model string, requestType *int16, stream *bool, billingType *int8) ([]usagestats.EndpointStat, error) {
	return r.next.GetUpstreamEndpointStatsWithFilters(ctx, startTime, endTime, userID, apiKeyID, accountID, groupID, model, requestType, stream, billingType)
}

func (r *usageLogPendingRepository) GetGroupStatsWithFilters(ctx context.Context, startTime, endTime time.Time, userID, apiKeyID, accountID, groupID int64, requestType *int16, stream *bool, billingType *int8) ([]usagestats.GroupStat, error) {
	return r.next.GetGroupStatsWithFilters(ctx, startTime, endTime, userID, apiKeyID, accountID, groupID, requestType, stream, billingType)
}

func (r *usageLogPendingRepository) GetGroupStatsWithUsageFilters(ctx context.Context, startTime, endTime time.Time, filters usagestats.UsageLogFilters) ([]usagestats.GroupStat, error) {
	if filterRepo, ok := r.next.(interface {
		GetGroupStatsWithUsageFilters(context.Context, time.Time, time.Time, usagestats.UsageLogFilters) ([]usagestats.GroupStat, error)
	}); ok {
		return filterRepo.GetGroupStatsWithUsageFilters(ctx, startTime, endTime, filters)
	}
	return r.next.GetGroupStatsWithFilters(ctx, startTime, endTime, filters.UserID, filters.APIKeyID, filters.AccountID, filters.GroupID, filters.RequestType, filters.Stream, filters.BillingType)
}

func (r *usageLogPendingRepository) GetUserBreakdownStats(ctx context.Context, startTime, endTime time.Time, dim usagestats.UserBreakdownDimension, limit int) ([]usagestats.UserBreakdownItem, error) {
	return r.next.GetUserBreakdownStats(ctx, startTime, endTime, dim, limit)
}

func (r *usageLogPendingRepository) GetAllGroupUsageSummary(ctx context.Context, todayStart time.Time) ([]usagestats.GroupUsageSummary, error) {
	return r.next.GetAllGroupUsageSummary(ctx, todayStart)
}

func (r *usageLogPendingRepository) GetAPIKeyUsageTrend(ctx context.Context, startTime, endTime time.Time, granularity string, limit int) ([]usagestats.APIKeyUsageTrendPoint, error) {
	return r.next.GetAPIKeyUsageTrend(ctx, startTime, endTime, granularity, limit)
}

func (r *usageLogPendingRepository) GetUserUsageTrend(ctx context.Context, startTime, endTime time.Time, granularity string, limit int) ([]usagestats.UserUsageTrendPoint, error) {
	return r.next.GetUserUsageTrend(ctx, startTime, endTime, granularity, limit)
}

func (r *usageLogPendingRepository) GetUserSpendingRanking(ctx context.Context, startTime, endTime time.Time, limit int) (*usagestats.UserSpendingRankingResponse, error) {
	return r.next.GetUserSpendingRanking(ctx, startTime, endTime, limit)
}

func (r *usageLogPendingRepository) GetBatchUserUsageStats(ctx context.Context, userIDs []int64, startTime, endTime time.Time) (map[int64]*usagestats.BatchUserUsageStats, error) {
	return r.next.GetBatchUserUsageStats(ctx, userIDs, startTime, endTime)
}

func (r *usageLogPendingRepository) GetBatchAPIKeyUsageStats(ctx context.Context, apiKeyIDs []int64, startTime, endTime time.Time) (map[int64]*usagestats.BatchAPIKeyUsageStats, error) {
	return r.next.GetBatchAPIKeyUsageStats(ctx, apiKeyIDs, startTime, endTime)
}

func (r *usageLogPendingRepository) GetUserDashboardStats(ctx context.Context, userID int64) (*usagestats.UserDashboardStats, error) {
	return r.next.GetUserDashboardStats(ctx, userID)
}

func (r *usageLogPendingRepository) GetAPIKeyDashboardStats(ctx context.Context, apiKeyID int64) (*usagestats.UserDashboardStats, error) {
	return r.next.GetAPIKeyDashboardStats(ctx, apiKeyID)
}

func (r *usageLogPendingRepository) GetUserUsageTrendByUserID(ctx context.Context, userID int64, startTime, endTime time.Time, granularity string) ([]usagestats.TrendDataPoint, error) {
	return r.next.GetUserUsageTrendByUserID(ctx, userID, startTime, endTime, granularity)
}

func (r *usageLogPendingRepository) GetUserModelStats(ctx context.Context, userID int64, startTime, endTime time.Time) ([]usagestats.ModelStat, error) {
	return r.next.GetUserModelStats(ctx, userID, startTime, endTime)
}

func (r *usageLogPendingRepository) ListWithFilters(ctx context.Context, params pagination.PaginationParams, filters usagestats.UsageLogFilters) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return r.next.ListWithFilters(ctx, params, filters)
}

func (r *usageLogPendingRepository) GetGlobalStats(ctx context.Context, startTime, endTime time.Time) (*usagestats.UsageStats, error) {
	return r.next.GetGlobalStats(ctx, startTime, endTime)
}

func (r *usageLogPendingRepository) GetDashboardStatsWithRange(ctx context.Context, startTime, endTime time.Time) (*usagestats.DashboardStats, error) {
	if fetcher, ok := r.next.(interface {
		GetDashboardStatsWithRange(context.Context, time.Time, time.Time) (*usagestats.DashboardStats, error)
	}); ok {
		return fetcher.GetDashboardStatsWithRange(ctx, startTime, endTime)
	}
	return r.next.GetDashboardStats(ctx)
}

func (r *usageLogPendingRepository) GetStatsWithFilters(ctx context.Context, filters usagestats.UsageLogFilters) (*usagestats.UsageStats, error) {
	return r.next.GetStatsWithFilters(ctx, filters)
}

func (r *usageLogPendingRepository) GetAccountUsageStats(ctx context.Context, accountID int64, startTime, endTime time.Time) (*usagestats.AccountUsageStatsResponse, error) {
	return r.next.GetAccountUsageStats(ctx, accountID, startTime, endTime)
}

func (r *usageLogPendingRepository) GetUserStatsAggregated(ctx context.Context, userID int64, startTime, endTime time.Time) (*usagestats.UsageStats, error) {
	return r.next.GetUserStatsAggregated(ctx, userID, startTime, endTime)
}

func (r *usageLogPendingRepository) GetAPIKeyStatsAggregated(ctx context.Context, apiKeyID int64, startTime, endTime time.Time) (*usagestats.UsageStats, error) {
	return r.next.GetAPIKeyStatsAggregated(ctx, apiKeyID, startTime, endTime)
}

func (r *usageLogPendingRepository) GetAccountStatsAggregated(ctx context.Context, accountID int64, startTime, endTime time.Time) (*usagestats.UsageStats, error) {
	return r.next.GetAccountStatsAggregated(ctx, accountID, startTime, endTime)
}

func (r *usageLogPendingRepository) GetModelStatsAggregated(ctx context.Context, modelName string, startTime, endTime time.Time) (*usagestats.UsageStats, error) {
	return r.next.GetModelStatsAggregated(ctx, modelName, startTime, endTime)
}

func (r *usageLogPendingRepository) GetDailyStatsAggregated(ctx context.Context, userID int64, startTime, endTime time.Time) ([]map[string]any, error) {
	return r.next.GetDailyStatsAggregated(ctx, userID, startTime, endTime)
}

func (r *usageLogPendingRepository) GetGeminiUsageTotalsBatch(ctx context.Context, accountIDs []int64, startTime, endTime time.Time) (map[int64]service.GeminiUsageTotals, error) {
	if batchReader, ok := r.next.(interface {
		GetGeminiUsageTotalsBatch(context.Context, []int64, time.Time, time.Time) (map[int64]service.GeminiUsageTotals, error)
	}); ok {
		return batchReader.GetGeminiUsageTotalsBatch(ctx, accountIDs, startTime, endTime)
	}
	return make(map[int64]service.GeminiUsageTotals, len(accountIDs)), nil
}
