package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type serverWarnLogger struct {
	mu         sync.Mutex
	nextLogAt  time.Time
	suppressed int
	lastMsg    string
}

func (l *serverWarnLogger) log(prefix string, err error) {
	if err == nil {
		return
	}
	now := time.Now()
	msg := err.Error()

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Before(l.nextLogAt) {
		l.suppressed++
		l.lastMsg = msg
		return
	}
	if l.suppressed > 0 {
		logrus.Warnf("%s: %s (suppressed %d repeats)", prefix, l.lastMsg, l.suppressed)
	}
	logrus.Warnf("%s: %s", prefix, msg)
	l.lastMsg = msg
	l.nextLogAt = now.Add(2 * time.Second)
	l.suppressed = 0
}

func serverIsTooManyOpenFilesErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "too many open files")
}

func serverIsOpenWrtRuntime() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/config/network"); err == nil {
		return true
	}
	return false
}

func serverFDPerConnBudget() uint64 {
	defaultBudget := 3
	if runtime.GOOS == "linux" && serverIsOpenWrtRuntime() {
		defaultBudget = 4
	}
	if raw := strings.TrimSpace(os.Getenv("ANYTLS_SERVER_FD_PER_CONN")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 12 {
			return uint64(n)
		}
	}
	return uint64(defaultBudget)
}

func serverFDReserveDivisor() uint64 {
	if runtime.GOOS == "linux" && serverIsOpenWrtRuntime() {
		return 3
	}
	return 4
}

func serverFDReserveFloor() uint64 {
	if runtime.GOOS == "linux" && serverIsOpenWrtRuntime() {
		return 256
	}
	return 192
}

func serverInboundConnLimit() int {
	const (
		minLimit     = 128
		maxLimit     = 32768
		defaultLinux = 512
		defaultOther = 2048
	)
	if raw := strings.TrimSpace(os.Getenv("ANYTLS_SERVER_MAX_CONN")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= minLimit && n <= maxLimit {
			return n
		}
	}
	if nofile := serverCurrentNoFileLimit(); nofile > 0 {
		reserve := nofile / serverFDReserveDivisor()
		if reserve < serverFDReserveFloor() {
			reserve = serverFDReserveFloor()
		}
		if nofile <= reserve+uint64(minLimit) {
			return minLimit
		}
		usable := nofile - reserve
		limit := int(usable / serverFDPerConnBudget())
		if limit < minLimit {
			limit = minLimit
		}
		if limit > maxLimit {
			limit = maxLimit
		}
		return limit
	}
	if runtime.GOOS == "linux" {
		return defaultLinux
	}
	return defaultOther
}

func serverInboundSlotWaitTimeout() time.Duration {
	const (
		minMs = 100
		maxMs = 10000
	)
	if raw := strings.TrimSpace(os.Getenv("ANYTLS_SERVER_SLOT_WAIT_MS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			if n < minMs {
				n = minMs
			}
			if n > maxMs {
				n = maxMs
			}
			return time.Duration(n) * time.Millisecond
		}
	}
	if runtime.GOOS == "linux" && serverIsOpenWrtRuntime() {
		return 1200 * time.Millisecond
	}
	return 800 * time.Millisecond
}

func serverFDUsageSummary() string {
	limit := serverCurrentNoFileLimit()
	open := serverCurrentOpenFDCount()
	if limit == 0 || open < 0 {
		if limit > 0 {
			return fmt.Sprintf("nofile=%d", limit)
		}
		return "nofile=unknown"
	}
	pct := float64(open) * 100 / float64(limit)
	return fmt.Sprintf("fd=%d/%d(%.0f%%)", open, limit, pct)
}

func serverAdaptiveSoftLimit(connLimit int) (int, time.Duration, string) {
	fdOpen := serverCurrentOpenFDCount()
	fdLimit := serverCurrentNoFileLimit()
	if fdOpen <= 0 || fdLimit == 0 {
		return connLimit, 0, serverFDUsageSummary()
	}

	fdPct := float64(fdOpen) * 100 / float64(fdLimit)
	switch {
	case fdPct >= 97:
		soft := connLimit / 4
		if soft < 64 {
			soft = 64
		}
		if soft > connLimit {
			soft = connLimit
		}
		return soft, 150 * time.Millisecond, fmt.Sprintf("fd=%d/%d(%.0f%%)", fdOpen, fdLimit, fdPct)
	case fdPct >= 94:
		soft := connLimit / 2
		if soft < 128 {
			soft = 128
		}
		if soft > connLimit {
			soft = connLimit
		}
		return soft, 250 * time.Millisecond, fmt.Sprintf("fd=%d/%d(%.0f%%)", fdOpen, fdLimit, fdPct)
	case fdPct >= 90:
		soft := (connLimit * 3) / 4
		if soft < 192 {
			soft = 192
		}
		if soft > connLimit {
			soft = connLimit
		}
		return soft, 400 * time.Millisecond, fmt.Sprintf("fd=%d/%d(%.0f%%)", fdOpen, fdLimit, fdPct)
	default:
		return connLimit, 0, fmt.Sprintf("fd=%d/%d(%.0f%%)", fdOpen, fdLimit, fdPct)
	}
}

type serverPressureController struct {
	lastAt time.Time
	score  float64
}

func newServerPressureController() *serverPressureController {
	return &serverPressureController{
		lastAt: time.Now(),
		score:  0,
	}
}

func (c *serverPressureController) decay() {
	now := time.Now()
	if c.lastAt.IsZero() {
		c.lastAt = now
		return
	}
	elapsed := now.Sub(c.lastAt).Seconds()
	if elapsed <= 0 {
		return
	}
	c.score -= elapsed * 1.2
	if c.score < 0 {
		c.score = 0
	}
	c.lastAt = now
}

func (c *serverPressureController) onAcceptError(err error) {
	c.decay()
	if serverIsTooManyOpenFilesErr(err) {
		c.score += 3
		return
	}
	c.score += 0.4
}

func (c *serverPressureController) onPressureDrop() {
	c.decay()
	c.score += 0.15
}

func (c *serverPressureController) compute(connLimit int, emfileCooldownMS int64) (int, time.Duration, string) {
	c.decay()
	soft, waitCap, baseReason := serverAdaptiveSoftLimit(connLimit)

	fdOpen := serverCurrentOpenFDCount()
	fdLimit := serverCurrentNoFileLimit()
	fdLevel := 0
	if fdOpen > 0 && fdLimit > 0 {
		fdPct := float64(fdOpen) * 100 / float64(fdLimit)
		switch {
		case fdPct >= 97:
			fdLevel = 3
		case fdPct >= 94:
			fdLevel = 2
		case fdPct >= 90:
			fdLevel = 1
		}
	}
	if c.score < 0 {
		c.score = 0
	}

	scoreLevel := 0
	switch {
	case c.score >= 25:
		scoreLevel = 3
	case c.score >= 10:
		scoreLevel = 2
	case c.score >= 3:
		scoreLevel = 1
	}
	level := fdLevel
	if fdLevel >= 2 && scoreLevel > level {
		level = scoreLevel
	}
	if emfileCooldownMS > 0 && level < 3 {
		level = 3
	}
	if level <= 0 {
		return soft, waitCap, fmt.Sprintf("%s score=%.2f level=0", baseReason, c.score)
	}

	switch level {
	case 1:
		altSoft := (connLimit * 85) / 100
		if altSoft < 192 {
			altSoft = 192
		}
		if altSoft < soft {
			soft = altSoft
		}
		if waitCap == 0 || waitCap > 500*time.Millisecond {
			waitCap = 500 * time.Millisecond
		}
	case 2:
		altSoft := (connLimit * 65) / 100
		if altSoft < 128 {
			altSoft = 128
		}
		if altSoft < soft {
			soft = altSoft
		}
		if waitCap == 0 || waitCap > 300*time.Millisecond {
			waitCap = 300 * time.Millisecond
		}
	default:
		altSoft := (connLimit * 45) / 100
		if altSoft < 64 {
			altSoft = 64
		}
		if altSoft < soft {
			soft = altSoft
		}
		if waitCap == 0 || waitCap > 150*time.Millisecond {
			waitCap = 150 * time.Millisecond
		}
	}
	if soft > connLimit {
		soft = connLimit
	}
	if soft < 64 {
		soft = 64
	}
	return soft, waitCap, fmt.Sprintf("%s score=%.2f level=%d", baseReason, c.score, level)
}
