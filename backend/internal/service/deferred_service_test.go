package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDeferredServiceDisabledDoesNotQueueLastUsed(t *testing.T) {
	svc := NewDeferredServiceWithOptions(nil, nil, 10*time.Second, false)

	svc.ScheduleLastUsedUpdate(123)
	svc.flushLastUsed()

	count := 0
	svc.lastUsedUpdates.Range(func(_, _ any) bool {
		count++
		return true
	})
	require.Equal(t, 0, count)
}

func TestDeferredServiceEnabledQueuesLastUsed(t *testing.T) {
	svc := NewDeferredServiceWithOptions(nil, nil, 10*time.Second, true)

	svc.ScheduleLastUsedUpdate(123)

	_, ok := svc.lastUsedUpdates.Load(int64(123))
	require.True(t, ok)
}
