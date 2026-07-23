package repository

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type usageLogPendingBaseStub struct {
	service.UsageLogRepository

	createCalls     int
	bestEffortCalls int
	logs            []*service.UsageLog
	err             error
}

func (s *usageLogPendingBaseStub) Create(ctx context.Context, log *service.UsageLog) (bool, error) {
	s.createCalls++
	s.logs = append(s.logs, log)
	return true, s.err
}

func (s *usageLogPendingBaseStub) CreateBestEffort(ctx context.Context, log *service.UsageLog) error {
	s.bestEffortCalls++
	s.logs = append(s.logs, log)
	return s.err
}

func TestUsageLogPendingRepository_CreateBestEffortQueuesUntilFlush(t *testing.T) {
	base := &usageLogPendingBaseStub{}
	repo := &usageLogPendingRepository{
		next:    base,
		pending: make([]*service.UsageLog, 0),
		stopCh:  make(chan struct{}),
	}
	log := &service.UsageLog{
		RequestID: "usage-pending",
		UserID:    42,
		APIKeyID:  7,
		AccountID: 99,
		Model:     "gpt-4.1",
	}

	require.NoError(t, repo.CreateBestEffort(context.Background(), log))
	log.Model = "mutated-after-enqueue"

	stats := repo.Stats()
	require.Equal(t, 1, stats.PendingL1Entries)
	require.Equal(t, uint64(1), stats.EnqueuedTotal)
	require.Equal(t, 0, base.bestEffortCalls)

	repo.Flush(context.Background())

	require.Equal(t, 1, base.bestEffortCalls)
	require.Equal(t, 0, base.createCalls)
	require.Len(t, base.logs, 1)
	require.Equal(t, "gpt-4.1", base.logs[0].Model)
	stats = repo.Stats()
	require.Equal(t, 0, stats.PendingL1Entries)
	require.Equal(t, uint64(1), stats.FlushedTotal)
}
