package repository

import (
	"github.com/Wei-Shaw/sub2api/internal/hotpath"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func NewLocalConcurrencyCache(slotTTLMinutes int, waitQueueTTLSeconds int) service.ConcurrencyCache {
	return hotpath.NewLocalConcurrencyCache(slotTTLMinutes, waitQueueTTLSeconds)
}
