package main

import (
	"testing"
	"time"
)

func TestAuthAttemptGuardLockoutCycle(t *testing.T) {
	guard := newAuthAttemptGuard(2, 2*time.Second)
	key := "203.0.113.10"
	now := time.Unix(1000, 0)

	allowed, _ := guard.allowAt(key, now)
	if !allowed {
		t.Fatalf("expected initial request allowed")
	}

	locked, _ := guard.recordFailureAt(key, now)
	if locked {
		t.Fatalf("expected first failure not locked")
	}
	locked, lockDur := guard.recordFailureAt(key, now.Add(100*time.Millisecond))
	if !locked || lockDur <= 0 {
		t.Fatalf("expected lock after second failure, locked=%v lockDur=%v", locked, lockDur)
	}

	allowed, wait := guard.allowAt(key, now.Add(time.Second))
	if allowed || wait <= 0 {
		t.Fatalf("expected blocked during lock window, allowed=%v wait=%v", allowed, wait)
	}

	allowed, _ = guard.allowAt(key, now.Add(3*time.Second))
	if !allowed {
		t.Fatalf("expected allowed after lock window")
	}

	guard.recordSuccessAt(key, now.Add(3*time.Second))
	allowed, _ = guard.allowAt(key, now.Add(3*time.Second))
	if !allowed {
		t.Fatalf("expected allowed after success reset")
	}
}
