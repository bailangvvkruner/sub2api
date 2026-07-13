package repository

import (
	"github.com/Wei-Shaw/sub2api/internal/hotpath"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func newLocalBillingCacheWithOptions(next service.BillingCache, maxEntries int, writeThrough bool) service.BillingCache {
	return hotpath.NewLocalBillingCacheWithOptions(next, maxEntries, writeThrough)
}
