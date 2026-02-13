//go:build !windows

package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func raiseClientNoFileLimit() {
	if runtime.GOOS == "windows" {
		return
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		logrus.Warnf("[Client] read nofile limit failed: %v", err)
		return
	}
	soft := lim.Cur
	hard := lim.Max
	if hard == 0 || soft >= hard {
		return
	}
	target := hard
	if target > 65535 {
		target = 65535
	}
	if target <= soft {
		return
	}
	lim.Cur = target
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		logrus.Warnf("[Client] raise nofile limit failed: soft=%d hard=%d err=%v", soft, hard, err)
		return
	}
	logrus.Infof("[Client] nofile limit raised: %d -> %d (hard=%d)", soft, target, hard)
}

func currentNoFileLimit() uint64 {
	if runtime.GOOS == "windows" {
		return 0
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err == nil && lim.Cur > 0 {
		return lim.Cur
	}
	if n := parseProcSelfNoFileLimit(); n > 0 {
		return n
	}
	return parseShellNoFileLimit()
}

func parseProcSelfNoFileLimit() uint64 {
	f, err := os.Open("/proc/self/limits")
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Example:
		// Max open files            1024                 4096                 files
		// Max open files            unlimited            unlimited            files
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		soft := strings.ToLower(strings.TrimSpace(fields[3]))
		if soft == "unlimited" {
			return 1 << 20
		}
		n, err := strconv.ParseUint(soft, 10, 64)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

func parseShellNoFileLimit() uint64 {
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", "ulimit -n")
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	text := strings.ToLower(strings.TrimSpace(string(out)))
	if text == "" {
		return 0
	}
	if text == "unlimited" {
		return 1 << 20
	}
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
