package service

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func usagePendingInstanceKey(prefix string) string {
	host, _ := os.Hostname()
	host = strings.TrimSpace(host)
	if host == "" {
		host = "unknown"
	}
	return prefix + ":" + host + ":" + strconv.Itoa(os.Getpid())
}

func usagePendingTTL() time.Duration {
	return usagePendingL2TTL
}
