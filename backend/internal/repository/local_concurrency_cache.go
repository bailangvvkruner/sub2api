package repository

import (
	"github.com/Wei-Shaw/sub2api/internal/hotpath"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type localConcurrencyCacheWithLeases struct {
	service.ConcurrencyCache
	service.APIKeyConcurrencyCache
	service.OpenAIWSIngressLeaseCache
}

var _ service.ConcurrencyCache = (*localConcurrencyCacheWithLeases)(nil)
var _ service.APIKeyConcurrencyCache = (*localConcurrencyCacheWithLeases)(nil)
var _ service.OpenAIWSIngressLeaseCache = (*localConcurrencyCacheWithLeases)(nil)

func NewLocalConcurrencyCache(slotTTLMinutes int, waitQueueTTLSeconds int) service.ConcurrencyCache {
	return hotpath.NewLocalConcurrencyCache(slotTTLMinutes, waitQueueTTLSeconds)
}

func newLocalConcurrencyCacheWithLeases(local service.ConcurrencyCache, apiKeys service.APIKeyConcurrencyCache, leases service.OpenAIWSIngressLeaseCache) service.ConcurrencyCache {
	return &localConcurrencyCacheWithLeases{
		ConcurrencyCache:          local,
		APIKeyConcurrencyCache:    apiKeys,
		OpenAIWSIngressLeaseCache: leases,
	}
}
