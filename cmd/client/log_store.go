package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type clientLogEntry struct {
	ID      int64  `json:"id"`
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type clientLogStore struct {
	lock     sync.Mutex
	capacity int
	entries  []clientLogEntry
	nextID   int64
}

func newClientLogStore(capacity int) *clientLogStore {
	if capacity <= 0 {
		capacity = 4000
	}
	return &clientLogStore{
		capacity: capacity,
		entries:  make([]clientLogEntry, 0, capacity),
		nextID:   1,
	}
}

func (s *clientLogStore) append(level, message string, ts time.Time) {
	if s == nil {
		return
	}
	level = strings.ToLower(strings.TrimSpace(level))
	if level == "" {
		level = "info"
	}
	message = strings.TrimSpace(message)

	s.lock.Lock()
	defer s.lock.Unlock()

	item := clientLogEntry{
		ID:      s.nextID,
		Time:    ts.Format(time.RFC3339),
		Level:   level,
		Message: message,
	}
	s.nextID++
	s.entries = append(s.entries, item)
	if len(s.entries) > s.capacity {
		trim := len(s.entries) - s.capacity
		s.entries = append([]clientLogEntry(nil), s.entries[trim:]...)
	}
}

func (s *clientLogStore) list(limit int, level, search string, sinceID int64) []clientLogEntry {
	if s == nil {
		return nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	level = strings.ToLower(strings.TrimSpace(level))
	search = strings.ToLower(strings.TrimSpace(search))

	s.lock.Lock()
	defer s.lock.Unlock()

	out := make([]clientLogEntry, 0, limit)
	for i := len(s.entries) - 1; i >= 0; i-- {
		item := s.entries[i]
		if sinceID > 0 && item.ID <= sinceID {
			continue
		}
		if level != "" && item.Level != level {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(item.Message), search) {
			continue
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	// Keep ascending order for frontend rendering and incremental poll.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *clientLogStore) clear() {
	if s == nil {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.entries = s.entries[:0]
}

func (s *clientLogStore) latestID() int64 {
	if s == nil {
		return 0
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if len(s.entries) == 0 {
		return 0
	}
	return s.entries[len(s.entries)-1].ID
}

type clientLogHook struct{}

func (h *clientLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *clientLogHook) Fire(entry *logrus.Entry) error {
	if entry == nil {
		return nil
	}
	clientLogs.append(entry.Level.String(), formatLogMessage(entry), entry.Time)
	return nil
}

func formatLogMessage(entry *logrus.Entry) string {
	msg := strings.TrimSpace(entry.Message)
	if len(entry.Data) == 0 {
		return msg
	}

	keys := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	if msg != "" {
		b.WriteString(msg)
	}
	for _, k := range keys {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(fmt.Sprintf("%v", entry.Data[k]))
	}
	return b.String()
}

var (
	clientLogs         = newClientLogStore(4000)
	initLogCaptureOnce sync.Once
)

func initClientLogCapture() {
	initLogCaptureOnce.Do(func() {
		logrus.StandardLogger().AddHook(&clientLogHook{})
	})
}
