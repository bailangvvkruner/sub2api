package repository

import (
	"github.com/Wei-Shaw/sub2api/internal/hotpath"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func newLocalBillingCache(next service.BillingCache, maxEntries int) service.BillingCache {
	return hotpath.NewLocalBillingCache(next, maxEntries)
}

func newLocalBillingCacheWithOptions(next service.BillingCache, maxEntries int, writeThrough bool) service.BillingCache {
	return hotpath.NewLocalBillingCacheWithOptions(next, maxEntries, writeThrough)
}
