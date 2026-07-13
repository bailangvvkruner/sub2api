//go:build unit

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterByMinPriority(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result := filterByMinPriority(nil)
		require.Empty(t, result)
	})

	t.Run("single account", func(t *testing.T) {
		accounts := []accountWithLoad{
			{account: &Account{ID: 1, Priority: 5}, loadInfo: &AccountLoadInfo{}},
		}
		result := filterByMinPriority(accounts)
		require.Len(t, result, 1)
		require.Equal(t, int64(1), result[0].account.ID)
	})

	t.Run("multiple accounts same priority", func(t *testing.T) {
		accounts := []accountWithLoad{
			{account: &Account{ID: 1, Priority: 3}, loadInfo: &AccountLoadInfo{}},
			{account: &Account{ID: 2, Priority: 3}, loadInfo: &AccountLoadInfo{}},
			{account: &Account{ID: 3, Priority: 3}, loadInfo: &AccountLoadInfo{}},
		}
		result := filterByMinPriority(accounts)
		require.Len(t, result, 3)
	})

	t.Run("filters to min priority only", func(t *testing.T) {
		accounts := []accountWithLoad{
			{account: &Account{ID: 1, Priority: 5}, loadInfo: &AccountLoadInfo{}},
			{account: &Account{ID: 2, Priority: 1}, loadInfo: &AccountLoadInfo{}},
			{account: &Account{ID: 3, Priority: 3}, loadInfo: &AccountLoadInfo{}},
			{account: &Account{ID: 4, Priority: 1}, loadInfo: &AccountLoadInfo{}},
		}
		result := filterByMinPriority(accounts)
		require.Len(t, result, 2)
		require.Equal(t, int64(2), result[0].account.ID)
		require.Equal(t, int64(4), result[1].account.ID)
	})
}

func TestFilterByMinLoadRate(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result := filterByMinLoadRate(nil)
		require.Empty(t, result)
	})

	t.Run("single account", func(t *testing.T) {
		accounts := []accountWithLoad{
			{account: &Account{ID: 1}, loadInfo: &AccountLoadInfo{LoadRate: 50}},
		}
		result := filterByMinLoadRate(accounts)
		require.Len(t, result, 1)
		require.Equal(t, int64(1), result[0].account.ID)
	})

	t.Run("multiple accounts same load rate", func(t *testing.T) {
		accounts := []accountWithLoad{
			{account: &Account{ID: 1}, loadInfo: &AccountLoadInfo{LoadRate: 20}},
			{account: &Account{ID: 2}, loadInfo: &AccountLoadInfo{LoadRate: 20}},
			{account: &Account{ID: 3}, loadInfo: &AccountLoadInfo{LoadRate: 20}},
		}
		result := filterByMinLoadRate(accounts)
		require.Len(t, result, 3)
	})

	t.Run("filters to min load rate only", func(t *testing.T) {
		accounts := []accountWithLoad{
			{account: &Account{ID: 1}, loadInfo: &AccountLoadInfo{LoadRate: 80}},
			{account: &Account{ID: 2}, loadInfo: &AccountLoadInfo{LoadRate: 10}},
			{account: &Account{ID: 3}, loadInfo: &AccountLoadInfo{LoadRate: 50}},
			{account: &Account{ID: 4}, loadInfo: &AccountLoadInfo{LoadRate: 10}},
		}
		result := filterByMinLoadRate(accounts)
		require.Len(t, result, 2)
		require.Equal(t, int64(2), result[0].account.ID)
		require.Equal(t, int64(4), result[1].account.ID)
	})

	t.Run("zero load rate", func(t *testing.T) {
		accounts := []accountWithLoad{
			{account: &Account{ID: 1}, loadInfo: &AccountLoadInfo{LoadRate: 0}},
			{account: &Account{ID: 2}, loadInfo: &AccountLoadInfo{LoadRate: 50}},
			{account: &Account{ID: 3}, loadInfo: &AccountLoadInfo{LoadRate: 0}},
		}
		result := filterByMinLoadRate(accounts)
		require.Len(t, result, 2)
		require.Equal(t, int64(1), result[0].account.ID)
		require.Equal(t, int64(3), result[1].account.ID)
	})
}
