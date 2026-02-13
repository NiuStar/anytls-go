package main

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *apiState) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	sinceID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("since_id")), 10, 64)
	level := strings.TrimSpace(q.Get("level"))
	search := strings.TrimSpace(q.Get("search"))

	items := clientLogs.list(limit, level, search, sinceID)
	writeJSON(w, http.StatusOK, map[string]any{
		"items":     items,
		"latest_id": clientLogs.latestID(),
		"count":     len(items),
	})
}

func (s *apiState) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	clientLogs.clear()
	writeJSON(w, http.StatusOK, map[string]any{
		"cleared": true,
	})
}
