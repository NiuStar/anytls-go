package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAuthMaxFailures = 8
	defaultAuthLockoutSec  = 300
)

type authFailureState struct {
	count     int
	firstSeen time.Time
	lockUntil time.Time
}

type authAttemptGuard struct {
	lock sync.Mutex

	maxFailures int
	lockout     time.Duration
	window      time.Duration

	failures map[string]*authFailureState
}

func newAuthAttemptGuard(maxFailures int, lockout time.Duration) *authAttemptGuard {
	if maxFailures <= 0 {
		maxFailures = defaultAuthMaxFailures
	}
	if lockout <= 0 {
		lockout = time.Duration(defaultAuthLockoutSec) * time.Second
	}
	return &authAttemptGuard{
		maxFailures: maxFailures,
		lockout:     lockout,
		window:      lockout,
		failures:    make(map[string]*authFailureState),
	}
}

func newAuthAttemptGuardFromEnv() *authAttemptGuard {
	maxFailures := parsePositiveIntEnv("ANYTLS_API_AUTH_MAX_FAILURES", defaultAuthMaxFailures)
	lockoutSec := parsePositiveIntEnv("ANYTLS_API_AUTH_LOCKOUT_SEC", defaultAuthLockoutSec)
	return newAuthAttemptGuard(maxFailures, time.Duration(lockoutSec)*time.Second)
}

func parsePositiveIntEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func (g *authAttemptGuard) allow(key string) (bool, time.Duration) {
	return g.allowAt(key, time.Now())
}

func (g *authAttemptGuard) recordFailure(key string) (bool, time.Duration) {
	return g.recordFailureAt(key, time.Now())
}

func (g *authAttemptGuard) recordSuccess(key string) {
	g.recordSuccessAt(key, time.Now())
}

func (g *authAttemptGuard) allowAt(key string, now time.Time) (bool, time.Duration) {
	if g == nil || strings.TrimSpace(key) == "" {
		return true, 0
	}

	g.lock.Lock()
	defer g.lock.Unlock()
	g.cleanupLocked(now)

	state, ok := g.failures[key]
	if !ok {
		return true, 0
	}
	if state.lockUntil.After(now) {
		return false, state.lockUntil.Sub(now)
	}
	return true, 0
}

func (g *authAttemptGuard) recordFailureAt(key string, now time.Time) (bool, time.Duration) {
	if g == nil || strings.TrimSpace(key) == "" {
		return false, 0
	}

	g.lock.Lock()
	defer g.lock.Unlock()
	g.cleanupLocked(now)

	state, ok := g.failures[key]
	if !ok {
		state = &authFailureState{count: 1, firstSeen: now}
		g.failures[key] = state
	} else {
		if now.Sub(state.firstSeen) > g.window {
			state.count = 0
			state.firstSeen = now
		}
		state.count++
	}

	if state.count >= g.maxFailures {
		state.lockUntil = now.Add(g.lockout)
		state.count = 0
		state.firstSeen = now
		return true, g.lockout
	}
	return false, 0
}

func (g *authAttemptGuard) recordSuccessAt(key string, now time.Time) {
	if g == nil || strings.TrimSpace(key) == "" {
		return
	}
	g.lock.Lock()
	defer g.lock.Unlock()
	g.cleanupLocked(now)
	delete(g.failures, key)
}

func (g *authAttemptGuard) cleanupLocked(now time.Time) {
	for key, state := range g.failures {
		if state.lockUntil.IsZero() && now.Sub(state.firstSeen) > g.window {
			delete(g.failures, key)
			continue
		}
		if !state.lockUntil.IsZero() && !state.lockUntil.After(now) {
			delete(g.failures, key)
		}
	}
}
