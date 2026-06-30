package repository

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func BenchmarkConcurrencyCacheHotPath(b *testing.B) {
	rdb := newHotPathBenchmarkRedisClient(b)
	defer func() { _ = rdb.Close() }()

	cases := []struct {
		name  string
		cache service.ConcurrencyCache
	}{
		{name: "redis_zset", cache: NewConcurrencyCache(rdb, benchSlotTTLMinutes, int(benchSlotTTL.Seconds()))},
		{name: "local_memory", cache: NewLocalConcurrencyCache(benchSlotTTLMinutes, int(benchSlotTTL.Seconds()))},
	}

	for _, tc := range cases {
		tc := tc
		b.Run(tc.name+"/acquire_release", func(b *testing.B) {
			benchmarkHotPathAcquireRelease(b, tc.cache)
		})
		b.Run(tc.name+"/acquire_release_parallel", func(b *testing.B) {
			benchmarkHotPathAcquireReleaseParallel(b, tc.cache)
		})
		b.Run(tc.name+"/load_batch_100", func(b *testing.B) {
			benchmarkHotPathLoadBatch(b, tc.cache, 100)
		})
	}
}

func benchmarkHotPathAcquireRelease(b *testing.B, cache service.ConcurrencyCache) {
	ctx := context.Background()
	accountID := time.Now().UnixNano()
	requestID := "bench-request"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acquired, err := cache.AcquireAccountSlot(ctx, accountID, 1_000_000, requestID)
		if err != nil {
			b.Fatalf("acquire account slot: %v", err)
		}
		if !acquired {
			b.Fatal("account slot was not acquired")
		}
		if err := cache.ReleaseAccountSlot(ctx, accountID, requestID); err != nil {
			b.Fatalf("release account slot: %v", err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

func benchmarkHotPathAcquireReleaseParallel(b *testing.B, cache service.ConcurrencyCache) {
	ctx := context.Background()
	accountID := time.Now().UnixNano()
	var seq atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			requestID := "bench-" + strconv.FormatUint(seq.Add(1), 36)
			acquired, err := cache.AcquireAccountSlot(ctx, accountID, 1_000_000, requestID)
			if err != nil {
				b.Fatalf("acquire account slot: %v", err)
			}
			if !acquired {
				b.Fatal("account slot was not acquired")
			}
			if err := cache.ReleaseAccountSlot(ctx, accountID, requestID); err != nil {
				b.Fatalf("release account slot: %v", err)
			}
		}
	})
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

func benchmarkHotPathLoadBatch(b *testing.B, cache service.ConcurrencyCache, size int) {
	ctx := context.Background()
	accounts := makeBenchmarkAccounts(size)
	seedBenchmarkAccountLoads(b, cache, accounts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loadMap, err := cache.GetAccountsLoadBatch(ctx, accounts)
		if err != nil {
			b.Fatalf("get accounts load batch: %v", err)
		}
		if len(loadMap) != len(accounts) {
			b.Fatalf("load map size = %d, want %d", len(loadMap), len(accounts))
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

func makeBenchmarkAccounts(size int) []service.AccountWithConcurrency {
	baseID := time.Now().UnixNano()
	accounts := make([]service.AccountWithConcurrency, 0, size)
	for i := 0; i < size; i++ {
		accounts = append(accounts, service.AccountWithConcurrency{
			ID:             baseID + int64(i),
			MaxConcurrency: 20,
		})
	}
	return accounts
}

func seedBenchmarkAccountLoads(b *testing.B, cache service.ConcurrencyCache, accounts []service.AccountWithConcurrency) {
	b.Helper()

	ctx := context.Background()
	for _, account := range accounts {
		for slot := 0; slot < 3; slot++ {
			requestID := fmt.Sprintf("seed-%d-%d", account.ID, slot)
			acquired, err := cache.AcquireAccountSlot(ctx, account.ID, account.MaxConcurrency, requestID)
			if err != nil {
				b.Fatalf("seed account slot: %v", err)
			}
			if !acquired {
				b.Fatalf("seed account slot was not acquired for account %d", account.ID)
			}
		}
		ok, err := cache.IncrementAccountWaitCount(ctx, account.ID, account.MaxConcurrency)
		if err != nil {
			b.Fatalf("seed account wait count: %v", err)
		}
		if !ok {
			b.Fatalf("seed account wait count was not allowed for account %d", account.ID)
		}
	}
}

func newHotPathBenchmarkRedisClient(b *testing.B) *redis.Client {
	b.Helper()

	if redisURL := os.Getenv("TEST_REDIS_URL"); redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			b.Fatalf("parse TEST_REDIS_URL: %v", err)
		}
		client := redis.NewClient(opt)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := client.Ping(ctx).Err(); err != nil {
			b.Fatalf("redis ping: %v", err)
		}
		return client
	}

	mr := miniredis.RunT(b)
	b.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}
