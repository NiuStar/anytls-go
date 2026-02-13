package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/sirupsen/logrus"
)

type subscriptionNodeItem struct {
	Name   string
	URI    string
	Groups []string
}

type subscriptionUpdateResult struct {
	ID           string                    `json:"id"`
	Name         string                    `json:"name"`
	Added        int                       `json:"added"`
	Updated      int                       `json:"updated"`
	Removed      int                       `json:"removed"`
	Total        int                       `json:"total"`
	SourceFmt    string                    `json:"source_format,omitempty"`
	Warning      string                    `json:"warning,omitempty"`
	ParseSummary *subscriptionParseSummary `json:"parse_summary,omitempty"`
	Error        string                    `json:"error,omitempty"`
	DurationM    int64                     `json:"duration_ms,omitempty"`
}

type subscriptionRuntimeStatus struct {
	Updating      bool
	LastAttemptAt time.Time
	LastSuccessAt time.Time
	LastError     string
	LastResult    subscriptionUpdateResult
}

type subscriptionParseFieldCount struct {
	Field string `json:"field"`
	Count int    `json:"count"`
}

type subscriptionParseSummary struct {
	SkippedUnsupported int                           `json:"skipped_unsupported,omitempty"`
	SkippedInvalid     int                           `json:"skipped_invalid,omitempty"`
	PartialMapped      int                           `json:"partial_mapped,omitempty"`
	IgnoredFieldCount  int                           `json:"ignored_field_count,omitempty"`
	IgnoredFieldTop    []subscriptionParseFieldCount `json:"ignored_field_top,omitempty"`
}

func buildSubscriptionParseSummary(skippedUnsupported, skippedInvalid, partialMapped, ignoredFieldCount int, ignoredFieldTop map[string]int) *subscriptionParseSummary {
	summary := &subscriptionParseSummary{
		SkippedUnsupported: skippedUnsupported,
		SkippedInvalid:     skippedInvalid,
		PartialMapped:      partialMapped,
		IgnoredFieldCount:  ignoredFieldCount,
	}
	if len(ignoredFieldTop) > 0 {
		keys := make([]string, 0, len(ignoredFieldTop))
		for k, v := range ignoredFieldTop {
			if strings.TrimSpace(k) == "" || v <= 0 {
				continue
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			ci := ignoredFieldTop[keys[i]]
			cj := ignoredFieldTop[keys[j]]
			if ci == cj {
				return keys[i] < keys[j]
			}
			return ci > cj
		})
		limit := len(keys)
		if limit > 6 {
			limit = 6
		}
		if limit > 0 {
			summary.IgnoredFieldTop = make([]subscriptionParseFieldCount, 0, limit)
			for _, key := range keys[:limit] {
				summary.IgnoredFieldTop = append(summary.IgnoredFieldTop, subscriptionParseFieldCount{
					Field: key,
					Count: ignoredFieldTop[key],
				})
			}
		}
	}
	if summary.SkippedUnsupported <= 0 &&
		summary.SkippedInvalid <= 0 &&
		summary.PartialMapped <= 0 &&
		summary.IgnoredFieldCount <= 0 &&
		len(summary.IgnoredFieldTop) == 0 {
		return nil
	}
	return summary
}

func formatSubscriptionParseWarning(summary *subscriptionParseSummary) string {
	if summary == nil {
		return ""
	}
	warnings := make([]string, 0, 3)
	if summary.SkippedUnsupported > 0 {
		warnings = append(warnings, fmt.Sprintf("skipped %d unsupported proxies", summary.SkippedUnsupported))
	}
	if summary.SkippedInvalid > 0 {
		warnings = append(warnings, fmt.Sprintf("skipped %d invalid proxies", summary.SkippedInvalid))
	}
	if summary.PartialMapped > 0 {
		topMap := make(map[string]int, len(summary.IgnoredFieldTop))
		for _, item := range summary.IgnoredFieldTop {
			topMap[item.Field] = item.Count
		}
		warnings = append(warnings, fmt.Sprintf("mapped %d proxies with %d ignored field(s): %s", summary.PartialMapped, summary.IgnoredFieldCount, formatIgnoredFieldSummary(topMap, 4)))
	}
	return strings.Join(warnings, "; ")
}

func (s *apiState) startSubscriptionScheduler() {
	s.lock.Lock()
	if s.subCancel != nil {
		s.subCancel()
		s.subCancel = nil
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.subCancel = cancel
	s.lock.Unlock()

	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runSubscriptionTick(ctx)
			}
		}
	}()
}

func (s *apiState) stopSubscriptionScheduler() {
	s.lock.Lock()
	cancel := s.subCancel
	s.subCancel = nil
	s.lock.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *apiState) runSubscriptionTick(ctx context.Context) {
	now := time.Now()
	s.lock.Lock()
	subs := append([]clientSubscription(nil), s.cfg.Subscriptions...)
	dueIDs := make([]string, 0, len(subs))
	for _, sub := range subs {
		if !sub.Enabled {
			continue
		}
		status := s.ensureSubscriptionStatusLocked(sub.ID)
		if status.Updating {
			continue
		}
		interval := time.Duration(sub.UpdateIntervalSec) * time.Second
		if interval <= 0 {
			interval = time.Hour
		}
		if status.LastAttemptAt.IsZero() || now.Sub(status.LastAttemptAt) >= interval {
			dueIDs = append(dueIDs, sub.ID)
		}
	}
	s.lock.Unlock()

	for _, id := range dueIDs {
		if _, err := s.updateSubscriptionByID(ctx, id); err != nil {
			logrus.Warnln("[Client] subscription update failed:", id, err)
		}
	}
}

func (s *apiState) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.lock.Lock()
		defer s.lock.Unlock()
		items := make([]map[string]any, 0, len(s.cfg.Subscriptions))
		for _, sub := range s.cfg.Subscriptions {
			items = append(items, s.subscriptionWithStatusLocked(sub))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
			"count": len(items),
		})
	case http.MethodPost:
		var req clientSubscription
		if err := decodeJSONBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := normalizeSubscription(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.lock.Lock()
		defer s.lock.Unlock()
		if _, idx := findSubscriptionByID(s.cfg.Subscriptions, req.ID); idx >= 0 {
			writeError(w, http.StatusConflict, "subscription id already exists")
			return
		}
		s.cfg.Subscriptions = append(s.cfg.Subscriptions, req)
		if err := saveClientConfig(s.configPath, s.cfg); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.ensureSubscriptionStatusLocked(req.ID)
		writeJSON(w, http.StatusOK, map[string]any{
			"item": s.subscriptionWithStatusLocked(req),
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *apiState) handleSubscriptionByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/subscriptions/"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req struct {
			Name              *string   `json:"name"`
			URL               *string   `json:"url"`
			Enabled           *bool     `json:"enabled"`
			UpdateIntervalSec *int      `json:"update_interval_sec"`
			NodePrefix        *string   `json:"node_prefix"`
			Groups            *[]string `json:"groups"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.lock.Lock()
		defer s.lock.Unlock()
		_, idx := findSubscriptionByID(s.cfg.Subscriptions, id)
		if idx < 0 {
			writeError(w, http.StatusNotFound, "subscription not found")
			return
		}
		target := s.cfg.Subscriptions[idx]
		if req.Name != nil {
			target.Name = strings.TrimSpace(*req.Name)
		}
		if req.URL != nil {
			v := strings.TrimSpace(*req.URL)
			if v == "" {
				writeError(w, http.StatusBadRequest, "url cannot be empty")
				return
			}
			target.URL = v
		}
		if req.UpdateIntervalSec != nil {
			if *req.UpdateIntervalSec <= 0 {
				writeError(w, http.StatusBadRequest, "update_interval_sec must be > 0")
				return
			}
			target.UpdateIntervalSec = *req.UpdateIntervalSec
		}
		if req.NodePrefix != nil {
			target.NodePrefix = strings.TrimSpace(*req.NodePrefix)
		}
		if req.Groups != nil {
			target.Groups = normalizeNodeGroups(*req.Groups)
		}
		if req.Enabled != nil {
			target.Enabled = *req.Enabled
		}
		target.ID = id
		if err := normalizeSubscription(&target); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.cfg.Subscriptions[idx] = target
		if err := saveClientConfig(s.configPath, s.cfg); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"item": s.subscriptionWithStatusLocked(target),
		})
	case http.MethodDelete:
		s.lock.Lock()
		defer s.lock.Unlock()
		if err := s.deleteSubscriptionLocked(id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"deleted": id,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *apiState) handleSubscriptionUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.maybeHandleAsyncTask(w, r, "subscription_update", http.MethodPost, "/api/v1/subscriptions/update", req, s.handleSubscriptionUpdate) {
		return
	}

	targetID := strings.TrimSpace(req.ID)
	ids := make([]string, 0)
	s.lock.Lock()
	if targetID != "" {
		if _, idx := findSubscriptionByID(s.cfg.Subscriptions, targetID); idx < 0 {
			s.lock.Unlock()
			writeError(w, http.StatusNotFound, "subscription not found")
			return
		}
		ids = append(ids, targetID)
	} else {
		for _, sub := range s.cfg.Subscriptions {
			if sub.Enabled {
				ids = append(ids, sub.ID)
			}
		}
	}
	s.lock.Unlock()
	if len(ids) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"results": []subscriptionUpdateResult{},
			"count":   0,
		})
		return
	}

	results := make([]subscriptionUpdateResult, 0, len(ids))
	failed := 0
	for _, id := range ids {
		start := time.Now()
		result, err := s.updateSubscriptionByID(r.Context(), id)
		result.DurationM = time.Since(start).Milliseconds()
		if err != nil {
			result.Error = err.Error()
			failed++
		}
		results = append(results, result)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"count":   len(results),
		"failed":  failed,
	})
}

func (s *apiState) updateSubscriptionByID(ctx context.Context, id string) (subscriptionUpdateResult, error) {
	s.lock.Lock()
	sub, idx := findSubscriptionByID(s.cfg.Subscriptions, id)
	if idx < 0 {
		s.lock.Unlock()
		return subscriptionUpdateResult{ID: id}, fmt.Errorf("subscription not found")
	}
	status := s.ensureSubscriptionStatusLocked(id)
	if status.Updating {
		s.lock.Unlock()
		return subscriptionUpdateResult{ID: id, Name: sub.Name}, fmt.Errorf("subscription is updating")
	}
	status.Updating = true
	status.LastAttemptAt = time.Now()
	s.lock.Unlock()

	defer func() {
		s.lock.Lock()
		status := s.ensureSubscriptionStatusLocked(id)
		status.Updating = false
		s.lock.Unlock()
	}()

	items, warning, sourceFmt, parseSummary, err := fetchSubscriptionNodes(ctx, sub.URL)
	if err != nil {
		s.lock.Lock()
		st := s.ensureSubscriptionStatusLocked(id)
		st.LastError = err.Error()
		s.lock.Unlock()
		result := subscriptionUpdateResult{ID: sub.ID, Name: sub.Name, SourceFmt: sourceFmt, ParseSummary: parseSummary}
		if warning != "" {
			result.Warning = warning
		}
		return result, err
	}

	s.lock.Lock()
	result, err := s.applySubscriptionNodesLocked(sub, items)
	result.SourceFmt = sourceFmt
	if warning != "" {
		result.Warning = warning
	}
	result.ParseSummary = parseSummary
	st := s.ensureSubscriptionStatusLocked(id)
	if err != nil {
		st.LastError = err.Error()
		s.lock.Unlock()
		return result, err
	}
	st.LastError = ""
	st.LastSuccessAt = time.Now()
	st.LastResult = result
	s.lock.Unlock()
	return result, nil
}

func (s *apiState) applySubscriptionNodesLocked(sub clientSubscription, items []subscriptionNodeItem) (subscriptionUpdateResult, error) {
	result := subscriptionUpdateResult{ID: sub.ID, Name: sub.Name}
	if len(items) == 0 {
		return result, fmt.Errorf("subscription contains no valid nodes")
	}

	existingSource := make(map[string]string, len(s.cfg.Nodes))
	for _, n := range s.cfg.Nodes {
		existingSource[n.Name] = n.SourceID
	}
	desired := make(map[string]clientNodeConfig, len(items))
	used := make(map[string]struct{}, len(items))
	for i, item := range items {
		server, password, sni, egressIP, egressRule, err := parseNodeURI(item.URI)
		if err != nil {
			continue
		}
		baseName := strings.TrimSpace(item.Name)
		if baseName == "" {
			baseName = fmt.Sprintf("%s-%d", sub.NodePrefix, i+1)
		}
		name := allocateSubscriptionNodeName(baseName, sub.ID, existingSource, used)
		mergedGroups := normalizeNodeGroups(append(append([]string(nil), sub.Groups...), item.Groups...))
		desired[name] = clientNodeConfig{
			Name:       name,
			Server:     server,
			Password:   password,
			SNI:        sni,
			EgressIP:   egressIP,
			EgressRule: egressRule,
			Groups:     mergedGroups,
			SourceID:   sub.ID,
			URI:        strings.TrimSpace(item.URI),
		}
	}
	if len(desired) == 0 {
		return result, fmt.Errorf("subscription contains no valid uri")
	}

	oldNodes := s.cfg.Nodes
	newNodes := make([]clientNodeConfig, 0, len(oldNodes)+len(desired))
	removed := make([]string, 0)
	desiredNames := make(map[string]struct{}, len(desired))
	for name := range desired {
		desiredNames[name] = struct{}{}
	}

	for _, n := range oldNodes {
		if n.SourceID != sub.ID {
			newNodes = append(newNodes, n)
			continue
		}
		next, ok := desired[n.Name]
		if !ok {
			removed = append(removed, n.Name)
			continue
		}
		newNodes = append(newNodes, next)
		delete(desired, n.Name)
		result.Updated++
	}

	addNames := make([]string, 0, len(desired))
	for name := range desired {
		addNames = append(addNames, name)
	}
	sort.Strings(addNames)
	for _, name := range addNames {
		newNodes = append(newNodes, desired[name])
		result.Added++
	}
	result.Removed = len(removed)
	result.Total = len(desiredNames)

	if len(newNodes) == 0 {
		return result, fmt.Errorf("cannot remove all nodes")
	}

	s.cfg.Nodes = newNodes
	currentBefore := s.manager.CurrentNodeName()
	removedSet := make(map[string]struct{}, len(removed))
	for _, name := range removed {
		removedSet[name] = struct{}{}
	}

	switchTarget := ""
	if _, removedCurrent := removedSet[currentBefore]; removedCurrent {
		switchTarget = s.cfg.Nodes[0].Name
	}
	if _, ok := findNodeByName(s.cfg.Nodes, s.cfg.DefaultNode); !ok {
		if switchTarget != "" {
			s.cfg.DefaultNode = switchTarget
		} else if _, ok := findNodeByName(s.cfg.Nodes, currentBefore); ok {
			s.cfg.DefaultNode = currentBefore
		} else {
			s.cfg.DefaultNode = s.cfg.Nodes[0].Name
		}
	}

	if err := saveClientConfig(s.configPath, s.cfg); err != nil {
		return result, err
	}

	for _, name := range removed {
		s.manager.DeleteNode(name)
	}
	for _, node := range s.cfg.Nodes {
		if node.SourceID == sub.ID {
			s.manager.UpsertNode(node)
		}
	}

	if switchTarget != "" {
		if err := s.manager.Switch(switchTarget); err != nil {
			return result, err
		}
		if s.tun != nil {
			node, ok := findNodeByName(s.cfg.Nodes, switchTarget)
			if ok {
				if err := s.tun.OnSwitch(node); err != nil {
					return result, err
				}
			}
		}
	} else if _, ok := desiredNames[currentBefore]; ok {
		if err := s.refreshCurrentIfUpdated(currentBefore); err != nil {
			return result, err
		}
	}
	return result, nil
}

func allocateSubscriptionNodeName(base, subID string, existingSource map[string]string, used map[string]struct{}) string {
	base = sanitizeNodeName(strings.TrimSpace(base))
	if base == "" {
		base = "node"
	}
	candidate := base
	seq := 2
	for {
		if _, ok := used[candidate]; ok {
			candidate = base + "-" + strconv.Itoa(seq)
			seq++
			continue
		}
		if source, exists := existingSource[candidate]; exists && source != subID {
			candidate = base + "-" + strconv.Itoa(seq)
			seq++
			continue
		}
		used[candidate] = struct{}{}
		return candidate
	}
}

func (s *apiState) deleteSubscriptionLocked(id string) error {
	sub, idx := findSubscriptionByID(s.cfg.Subscriptions, id)
	if idx < 0 {
		return fmt.Errorf("subscription not found")
	}
	_ = sub

	newSubs := make([]clientSubscription, 0, len(s.cfg.Subscriptions)-1)
	newSubs = append(newSubs, s.cfg.Subscriptions[:idx]...)
	newSubs = append(newSubs, s.cfg.Subscriptions[idx+1:]...)
	s.cfg.Subscriptions = newSubs

	removed := make([]string, 0)
	newNodes := make([]clientNodeConfig, 0, len(s.cfg.Nodes))
	for _, n := range s.cfg.Nodes {
		if n.SourceID == id {
			removed = append(removed, n.Name)
			continue
		}
		newNodes = append(newNodes, n)
	}
	if len(newNodes) == 0 {
		return fmt.Errorf("cannot remove all nodes")
	}
	s.cfg.Nodes = newNodes

	currentBefore := s.manager.CurrentNodeName()
	removedSet := make(map[string]struct{}, len(removed))
	for _, n := range removed {
		removedSet[n] = struct{}{}
	}
	switchTarget := ""
	if _, ok := removedSet[currentBefore]; ok {
		switchTarget = s.cfg.Nodes[0].Name
	}
	if _, ok := findNodeByName(s.cfg.Nodes, s.cfg.DefaultNode); !ok {
		if switchTarget != "" {
			s.cfg.DefaultNode = switchTarget
		} else if _, ok := findNodeByName(s.cfg.Nodes, currentBefore); ok {
			s.cfg.DefaultNode = currentBefore
		} else {
			s.cfg.DefaultNode = s.cfg.Nodes[0].Name
		}
	}

	if err := saveClientConfig(s.configPath, s.cfg); err != nil {
		return err
	}
	for _, n := range removed {
		s.manager.DeleteNode(n)
	}
	if switchTarget != "" {
		if err := s.manager.Switch(switchTarget); err != nil {
			return err
		}
		if s.tun != nil {
			node, ok := findNodeByName(s.cfg.Nodes, switchTarget)
			if ok {
				if err := s.tun.OnSwitch(node); err != nil {
					return err
				}
			}
		}
	}
	delete(s.subStatus, id)
	return nil
}

func (s *apiState) ensureSubscriptionStatusLocked(id string) *subscriptionRuntimeStatus {
	if s.subStatus == nil {
		s.subStatus = make(map[string]*subscriptionRuntimeStatus)
	}
	item, ok := s.subStatus[id]
	if ok {
		return item
	}
	item = &subscriptionRuntimeStatus{}
	s.subStatus[id] = item
	return item
}

func (s *apiState) subscriptionWithStatusLocked(sub clientSubscription) map[string]any {
	status := s.ensureSubscriptionStatusLocked(sub.ID)
	resp := map[string]any{
		"id":                  sub.ID,
		"name":                sub.Name,
		"url":                 sub.URL,
		"enabled":             sub.Enabled,
		"update_interval_sec": sub.UpdateIntervalSec,
		"node_prefix":         sub.NodePrefix,
		"groups":              sub.Groups,
		"status": map[string]any{
			"updating": status.Updating,
			"error":    status.LastError,
			"result":   status.LastResult,
		},
	}
	if !status.LastAttemptAt.IsZero() {
		resp["status"].(map[string]any)["last_attempt_at"] = status.LastAttemptAt.Format(time.RFC3339)
	}
	if !status.LastSuccessAt.IsZero() {
		resp["status"].(map[string]any)["last_success_at"] = status.LastSuccessAt.Format(time.RFC3339)
	}
	return resp
}

func findSubscriptionByID(subs []clientSubscription, id string) (clientSubscription, int) {
	for i, sub := range subs {
		if sub.ID == id {
			return sub, i
		}
	}
	return clientSubscription{}, -1
}

func fetchSubscriptionNodes(ctx context.Context, rawURL string) ([]subscriptionNodeItem, string, string, *subscriptionParseSummary, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	client := newRuntimeHTTPClient(25 * time.Second)
	requestURLs := runtimeRequestURLCandidates(rawURL)
	var lastErr error
	for idx, requestURL := range requestURLs {
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, "", "", nil, err
		}
		req.Header.Set("User-Agent", "anytls-client-subscription/1.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if idx == 0 && len(requestURLs) > 1 {
				continue
			}
			return nil, "", "", nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("http status %d", resp.StatusCode)
			if idx == 0 && len(requestURLs) > 1 {
				continue
			}
			return nil, "", "", nil, lastErr
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if idx == 0 && len(requestURLs) > 1 {
				continue
			}
			return nil, "", "", nil, readErr
		}
		items, warning, sourceFmt, parseSummary := parseSubscriptionContentWithMeta(raw)
		if len(items) == 0 {
			return nil, warning, sourceFmt, parseSummary, fmt.Errorf("subscription payload has no valid uri")
		}
		return items, warning, sourceFmt, parseSummary, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no request url candidate")
	}
	return nil, "", "", nil, lastErr
}

func parseSubscriptionContent(raw []byte) ([]subscriptionNodeItem, string, string) {
	items, warning, sourceFmt, _ := parseSubscriptionContentWithMeta(raw)
	return items, warning, sourceFmt
}

func parseSubscriptionContentWithMeta(raw []byte) ([]subscriptionNodeItem, string, string, *subscriptionParseSummary) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, "", "", nil
	}
	return parseSubscriptionContentTextWithMeta(text, 0)
}

func parseSubscriptionContentTextWithMeta(text string, depth int) ([]subscriptionNodeItem, string, string, *subscriptionParseSummary) {
	items, ok := parseSubscriptionJSON(text)
	if ok && len(items) > 0 {
		return items, "", "json", nil
	}
	if items, recognized, warning, parseSummary := parseClashSubscription(text); recognized {
		if len(items) > 0 {
			return dedupeSubscriptionItems(items), warning, "clash", parseSummary
		}
		if warning != "" {
			return nil, warning, "clash", parseSummary
		}
	}
	if items, recognized, warning, parseSummary := parseSurgeSubscription(text); recognized {
		if len(items) > 0 {
			return dedupeSubscriptionItems(items), warning, "surge", parseSummary
		}
		if warning != "" {
			return nil, warning, "surge", parseSummary
		}
	}
	items, warning := parseSubscriptionLines(text)
	if len(items) > 0 {
		return items, warning, "lines", nil
	}
	if depth == 0 {
		if decoded, ok := decodeBase64SubscriptionText(text); ok {
			if nextItems, nextWarning, nextFmt, nextSummary := parseSubscriptionContentTextWithMeta(decoded, depth+1); len(nextItems) > 0 {
				sourceFmt := "base64"
				if nextFmt != "" {
					sourceFmt += "->" + nextFmt
				}
				if nextWarning == "" {
					nextWarning = "decoded from base64 payload"
				}
				return nextItems, nextWarning, sourceFmt, nextSummary
			}
		}
	}
	return nil, warning, "", nil
}

func parseSubscriptionJSON(text string) ([]subscriptionNodeItem, bool) {
	if !(strings.HasPrefix(text, "[") || strings.HasPrefix(text, "{")) {
		return nil, false
	}

	var arr []any
	if err := json.Unmarshal([]byte(text), &arr); err == nil {
		return parseSubscriptionAnyArray(arr), true
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return nil, false
	}
	out := make([]subscriptionNodeItem, 0)
	for _, key := range []string{"nodes", "proxies", "items", "outbounds", "endpoints", "servers"} {
		if v, ok := obj[key]; ok {
			if arr, ok := v.([]any); ok {
				out = append(out, parseSubscriptionAnyArray(arr)...)
			}
		}
	}
	// Generic fallback for unknown keys that still look like proxy arrays.
	for rawKey, rawValue := range obj {
		key := strings.ToLower(strings.TrimSpace(rawKey))
		if key == "" {
			continue
		}
		if key == "nodes" || key == "proxies" || key == "items" || key == "outbounds" || key == "endpoints" || key == "servers" {
			continue
		}
		if !(strings.Contains(key, "proxy") || strings.Contains(key, "node") || strings.Contains(key, "outbound") || strings.Contains(key, "server") || strings.Contains(key, "endpoint")) {
			continue
		}
		arr, ok := rawValue.([]any)
		if !ok {
			continue
		}
		out = append(out, parseSubscriptionAnyArray(arr)...)
	}
	// Single-object fallback (for rare payloads with one outbound object at top-level).
	if item, ok := parseMapAnyTLSNode(obj); ok {
		out = append(out, item)
	}
	out = dedupeSubscriptionItems(out)
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func parseSubscriptionAnyArray(arr []any) []subscriptionNodeItem {
	out := make([]subscriptionNodeItem, 0, len(arr))
	for _, item := range arr {
		switch v := item.(type) {
		case string:
			uri := strings.TrimSpace(v)
			if hasSupportedNodeURIScheme(uri) {
				out = append(out, subscriptionNodeItem{URI: uri})
			}
		case map[string]any:
			name, _ := v["name"].(string)
			uri, _ := v["uri"].(string)
			if uri == "" {
				uri, _ = v["url"].(string)
			}
			uri = strings.TrimSpace(uri)
			if hasSupportedNodeURIScheme(uri) {
				out = append(out, subscriptionNodeItem{Name: strings.TrimSpace(name), URI: uri})
				continue
			}
			if item, ok := parseMapAnyTLSNode(v); ok {
				out = append(out, item)
			}
		}
	}
	return dedupeSubscriptionItems(out)
}

func parseSubscriptionLines(text string) ([]subscriptionNodeItem, string) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]subscriptionNodeItem, 0, len(lines))
	skipped := 0

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
		if hasSupportedNodeURIScheme(line) {
			out = append(out, subscriptionNodeItem{URI: line})
			continue
		}

		if idx := strings.Index(line, ","); idx > 0 {
			left := strings.TrimSpace(line[:idx])
			right := strings.TrimSpace(line[idx+1:])
			if hasSupportedNodeURIScheme(right) {
				out = append(out, subscriptionNodeItem{Name: left, URI: right})
				continue
			}
		}
		if idx := strings.Index(line, "="); idx > 0 {
			left := strings.TrimSpace(line[:idx])
			right := strings.TrimSpace(line[idx+1:])
			if hasSupportedNodeURIScheme(right) {
				out = append(out, subscriptionNodeItem{Name: left, URI: right})
				continue
			}
		}
		fields := strings.Fields(line)
		found := ""
		name := ""
		for _, f := range fields {
			if hasSupportedNodeURIScheme(f) {
				found = strings.TrimSpace(f)
				break
			}
			if name == "" {
				name = strings.TrimSpace(f)
			}
		}
		if found != "" {
			out = append(out, subscriptionNodeItem{Name: name, URI: found})
			continue
		}
		skipped++
	}

	warning := ""
	if skipped > 0 {
		warning = fmt.Sprintf("skipped %d invalid lines", skipped)
	}
	return dedupeSubscriptionItems(out), warning
}

func parseClashSubscription(text string) ([]subscriptionNodeItem, bool, string, *subscriptionParseSummary) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	proxiesIndent := -1
	proxyItemIndent := -1
	inProxies := false
	recognized := false
	type clashKeyScope struct {
		indent int
		key    string
	}
	keyScopes := make([]clashKeyScope, 0, 4)

	current := map[string]string{}
	partialMapped := 0
	ignoredFieldCount := 0
	ignoredFieldTop := make(map[string]int)
	flush := func(out *[]subscriptionNodeItem, skippedUnsupported, skippedInvalid *int) {
		if len(current) == 0 {
			return
		}
		proxyType := strings.ToLower(strings.TrimSpace(firstNonEmpty(current, "type", "protocol")))
		item, status := parseKVAnyTLSNode(current)
		switch status {
		case "ok":
			*out = append(*out, item)
			if proxyType != "" && proxyType != "anytls" {
				ignored := collectIgnoredProxyFields(proxyType, current)
				if len(ignored) > 0 {
					partialMapped++
					ignoredFieldCount += len(ignored)
					for _, key := range ignored {
						ignoredFieldTop[key]++
					}
				}
			}
		case "unsupported":
			*skippedUnsupported = *skippedUnsupported + 1
		default:
			*skippedInvalid = *skippedInvalid + 1
		}
		current = map[string]string{}
	}

	out := make([]subscriptionNodeItem, 0)
	skippedUnsupported := 0
	skippedInvalid := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))

		if !inProxies {
			key := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, ":")))
			if key == "proxies" && strings.HasSuffix(line, ":") {
				inProxies = true
				recognized = true
				proxiesIndent = indent
				proxyItemIndent = -1
				keyScopes = keyScopes[:0]
				current = map[string]string{}
			}
			continue
		}

		if indent <= proxiesIndent && !strings.HasPrefix(line, "-") {
			flush(&out, &skippedUnsupported, &skippedInvalid)
			break
		}
		if strings.HasPrefix(line, "-") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			// New proxy item starts at the same (or less) indent as first proxy item.
			if proxyItemIndent < 0 || indent <= proxyItemIndent {
				flush(&out, &skippedUnsupported, &skippedInvalid)
				proxyItemIndent = indent
				keyScopes = keyScopes[:0]
				if rest == "" {
					continue
				}
				if strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") {
					inline := parseInlineKVMap(strings.TrimSpace(rest[1 : len(rest)-1]))
					for k, v := range inline {
						current[k] = v
					}
					continue
				}
				if k, v, ok := parseKVLine(rest); ok {
					nk := normalizeKVKey(k)
					if nk != "" {
						current[nk] = v
						if v == "" {
							keyScopes = append(keyScopes, clashKeyScope{indent: indent, key: nk})
						}
					}
				}
				continue
			}

			// Nested list item under current key scope (e.g. alpn: [h2, h3]).
			if rest != "" && len(keyScopes) > 0 {
				targetKey := keyScopes[len(keyScopes)-1].key
				existing := strings.TrimSpace(current[targetKey])
				if existing == "" {
					current[targetKey] = rest
				} else {
					current[targetKey] = existing + "," + rest
				}
			}
			continue
		}
		if k, v, ok := parseKVLine(line); ok {
			nk := normalizeKVKey(k)
			if nk == "" {
				continue
			}
			for len(keyScopes) > 0 && indent <= keyScopes[len(keyScopes)-1].indent {
				keyScopes = keyScopes[:len(keyScopes)-1]
			}
			fullKey := nk
			if len(keyScopes) > 0 {
				fullKey = keyScopes[len(keyScopes)-1].key + "-" + nk
			}
			current[fullKey] = v
			if v == "" {
				keyScopes = append(keyScopes, clashKeyScope{indent: indent, key: fullKey})
			}
		}
	}
	flush(&out, &skippedUnsupported, &skippedInvalid)
	proxyGroups := parseClashProxyGroupMap(lines)
	if len(proxyGroups) > 0 {
		for i := range out {
			name := strings.TrimSpace(out[i].Name)
			if name == "" {
				continue
			}
			if groups, ok := proxyGroups[name]; ok && len(groups) > 0 {
				out[i].Groups = append([]string(nil), groups...)
			}
		}
	}

	if !recognized {
		return nil, false, "", nil
	}
	parseSummary := buildSubscriptionParseSummary(skippedUnsupported, skippedInvalid, partialMapped, ignoredFieldCount, ignoredFieldTop)
	if len(out) == 0 {
		return nil, true, fmt.Sprintf("clash payload found, but no valid supported proxy (unsupported=%d invalid=%d)", skippedUnsupported, skippedInvalid), parseSummary
	}
	return dedupeSubscriptionItems(out), true, formatSubscriptionParseWarning(parseSummary), parseSummary
}

func parseClashProxyGroupMap(lines []string) map[string][]string {
	if len(lines) == 0 {
		return nil
	}
	sectionIndent := -1
	inSection := false

	currentGroup := ""
	inGroupProxies := false
	proxiesIndent := -1

	out := make(map[string][]string)

	addProxyToGroup := func(proxyName string) {
		groupName := strings.TrimSpace(currentGroup)
		proxyName = stripYAMLInlineComment(proxyName)
		proxyName = strings.Trim(strings.TrimSpace(proxyName), `"'`)
		if groupName == "" || proxyName == "" || isSpecialClashProxyGroupTarget(proxyName) {
			return
		}
		list := append([]string(nil), out[proxyName]...)
		for _, g := range list {
			if g == groupName {
				return
			}
		}
		list = append(list, groupName)
		sort.Strings(list)
		out[proxyName] = list
	}

	resetGroup := func() {
		currentGroup = ""
		inGroupProxies = false
		proxiesIndent = -1
	}

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))

		if !inSection {
			key := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(trimmed, ":")))
			if key == "proxy-groups" && strings.HasSuffix(trimmed, ":") {
				inSection = true
				sectionIndent = indent
				resetGroup()
			}
			continue
		}

		if indent <= sectionIndent && !strings.HasPrefix(trimmed, "-") {
			break
		}

		if strings.HasPrefix(trimmed, "-") {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if inGroupProxies && indent > proxiesIndent {
				addProxyToGroup(rest)
				continue
			}

			resetGroup()
			if rest == "" {
				continue
			}
			if strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") {
				inline := parseInlineKVMap(strings.TrimSpace(rest[1 : len(rest)-1]))
				currentGroup = strings.TrimSpace(firstNonEmpty(inline, "name"))
				proxiesRaw := strings.TrimSpace(firstNonEmpty(inline, "proxies"))
				if proxiesRaw != "" {
					for _, proxy := range parseInlineListValues(proxiesRaw) {
						addProxyToGroup(proxy)
					}
				}
				continue
			}
			if k, v, ok := parseKVLine(rest); ok {
				key := normalizeKVKey(k)
				switch key {
				case "name":
					currentGroup = strings.TrimSpace(v)
				case "proxies":
					if strings.TrimSpace(v) == "" {
						inGroupProxies = true
						proxiesIndent = indent
					} else {
						for _, proxy := range parseInlineListValues(v) {
							addProxyToGroup(proxy)
						}
					}
				}
			}
			continue
		}

		if inGroupProxies && indent <= proxiesIndent {
			inGroupProxies = false
		}
		if k, v, ok := parseKVLine(trimmed); ok {
			key := normalizeKVKey(k)
			switch key {
			case "name":
				currentGroup = strings.TrimSpace(v)
			case "proxies":
				if strings.TrimSpace(v) == "" {
					inGroupProxies = true
					proxiesIndent = indent
				} else {
					inGroupProxies = false
					for _, proxy := range parseInlineListValues(v) {
						addProxyToGroup(proxy)
					}
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseInlineListValues(raw string) []string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	parts := splitCSVLoose(s)
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = stripYAMLInlineComment(part)
		v := strings.Trim(strings.TrimSpace(part), `"'`)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func isSpecialClashProxyGroupTarget(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "PROXY", "COMPATIBLE":
		return true
	default:
		return false
	}
}

func parseSurgeSubscription(text string) ([]subscriptionNodeItem, bool, string, *subscriptionParseSummary) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	section := ""
	recognized := false
	out := make([]subscriptionNodeItem, 0)
	skippedUnsupported := 0
	skippedInvalid := 0
	partialMapped := 0
	ignoredFieldCount := 0
	ignoredFieldTop := make(map[string]int)

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if section != "proxy" {
			continue
		}
		recognized = true
		idx := strings.Index(line, "=")
		if idx <= 0 {
			skippedInvalid++
			continue
		}
		name := strings.TrimSpace(line[:idx])
		right := strings.TrimSpace(line[idx+1:])
		parts := splitCSVLoose(right)
		if len(parts) < 3 {
			skippedInvalid++
			continue
		}
		proxyType := strings.ToLower(strings.TrimSpace(parts[0]))
		if proxyType == "" {
			skippedInvalid++
			continue
		}
		server := strings.TrimSpace(parts[1])
		port, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err != nil || port <= 0 || port > 65535 {
			skippedInvalid++
			continue
		}
		kv := map[string]string{
			"name":   name,
			"type":   proxyType,
			"server": server,
			"port":   strconv.Itoa(port),
		}
		for i, token := range parts[3:] {
			if key, val, ok := parseKVLine(token); ok {
				kv[normalizeKVKey(key)] = val
				continue
			}
			if i == 0 {
				kv["password"] = strings.Trim(strings.TrimSpace(token), `"'`)
			}
		}
		item, status := parseKVAnyTLSNode(kv)
		if status != "ok" {
			if status == "unsupported" {
				skippedUnsupported++
			} else {
				skippedInvalid++
			}
			continue
		}
		out = append(out, item)
		if proxyType != "" && proxyType != "anytls" {
			ignored := collectIgnoredProxyFields(proxyType, kv)
			if len(ignored) > 0 {
				partialMapped++
				ignoredFieldCount += len(ignored)
				for _, key := range ignored {
					ignoredFieldTop[key]++
				}
			}
		}
	}

	if !recognized {
		return nil, false, "", nil
	}
	parseSummary := buildSubscriptionParseSummary(skippedUnsupported, skippedInvalid, partialMapped, ignoredFieldCount, ignoredFieldTop)
	if len(out) == 0 {
		return nil, true, fmt.Sprintf("surge payload found, but no valid supported proxy (unsupported=%d invalid=%d)", skippedUnsupported, skippedInvalid), parseSummary
	}
	return dedupeSubscriptionItems(out), true, formatSubscriptionParseWarning(parseSummary), parseSummary
}

func parseMapAnyTLSNode(v map[string]any) (subscriptionNodeItem, bool) {
	kv := make(map[string]string, len(v))
	for rawKey, rawValue := range v {
		flattenSubscriptionKV(rawKey, rawValue, kv, 0)
	}
	item, status := parseKVAnyTLSNode(kv)
	return item, status == "ok"
}

func flattenSubscriptionKV(rawKey string, rawValue any, out map[string]string, depth int) {
	if out == nil || depth > 6 {
		return
	}
	key := normalizeKVKey(rawKey)
	if key == "" {
		return
	}
	switch tv := rawValue.(type) {
	case string:
		if v := strings.TrimSpace(tv); v != "" {
			out[key] = v
		}
	case float64:
		out[key] = strconv.Itoa(int(tv))
	case int:
		out[key] = strconv.Itoa(tv)
	case bool:
		if tv {
			out[key] = "true"
		} else {
			out[key] = "false"
		}
	case []any:
		items := make([]string, 0, len(tv))
		for _, item := range tv {
			s := strings.TrimSpace(fmt.Sprintf("%v", item))
			if s == "" {
				continue
			}
			items = append(items, s)
		}
		if len(items) > 0 {
			out[key] = strings.Join(items, ",")
		}
	case map[string]any:
		raw, err := json.Marshal(tv)
		if err == nil {
			out[key] = strings.TrimSpace(string(raw))
		}
		for childKey, childValue := range tv {
			childNorm := normalizeKVKey(childKey)
			if childNorm == "" {
				continue
			}
			flattenSubscriptionKV(key+"-"+childNorm, childValue, out, depth+1)
		}
	}
}

func parseKVAnyTLSNode(kv map[string]string) (subscriptionNodeItem, string) {
	name := strings.TrimSpace(firstNonEmpty(kv, "name", "label", "tag"))
	rawURI := strings.TrimSpace(firstNonEmpty(kv, "uri", "url", "link"))
	if hasSupportedNodeURIScheme(rawURI) {
		return subscriptionNodeItem{Name: name, URI: rawURI}, "ok"
	}

	proxyType := strings.ToLower(strings.TrimSpace(firstNonEmpty(kv, "type", "protocol")))
	if proxyType != "" && proxyType != "anytls" {
		uri, status := buildNativeURIFromKVProxy(proxyType, kv, name)
		if status != "ok" {
			return subscriptionNodeItem{}, status
		}
		return subscriptionNodeItem{Name: name, URI: uri}, "ok"
	}
	server := strings.TrimSpace(firstNonEmpty(kv, "server", "host", "hostname", "address"))
	portRaw := strings.TrimSpace(firstNonEmpty(kv, "port"))
	password := strings.TrimSpace(firstNonEmpty(kv, "password", "passwd", "pwd"))
	sni := strings.TrimSpace(firstNonEmpty(kv, "sni", "servername", "server-name", "server_name", "tls-server-name", "tls_server_name"))
	egressIP := strings.TrimSpace(firstNonEmpty(kv, "egress-ip", "egress_ip"))
	egressRule := strings.TrimSpace(firstNonEmpty(kv, "egress-rule", "egress_rule"))
	if server == "" || portRaw == "" || password == "" {
		return subscriptionNodeItem{}, "invalid"
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 || port > 65535 {
		return subscriptionNodeItem{}, "invalid"
	}
	hostPort := joinHostPortLoose(server, port)
	uri, err := buildAnyTLSURI(hostPort, password, sni, egressIP, egressRule)
	if err != nil {
		return subscriptionNodeItem{}, "invalid"
	}
	return subscriptionNodeItem{Name: name, URI: uri}, "ok"
}

func buildNativeURIFromKVProxy(proxyType string, kv map[string]string, name string) (string, string) {
	proxyType = strings.ToLower(strings.TrimSpace(proxyType))
	server := strings.TrimSpace(firstNonEmpty(kv, "server", "host", "hostname", "address", "ip"))
	if server == "" {
		return "", "invalid"
	}
	portRaw := strings.TrimSpace(firstNonEmpty(kv, "port", "server-port", "server_port", "remote-port", "remote_port"))
	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 || port > 65535 {
		return "", "invalid"
	}
	hostPort := joinHostPortLoose(server, port)
	fragment := strings.TrimSpace(name)
	switch proxyType {
	case "ss", "shadowsocks":
		method := strings.TrimSpace(firstNonEmpty(kv, "cipher", "method", "encrypt-method", "encrypt_method"))
		password := strings.TrimSpace(firstNonEmpty(kv, "password", "passwd", "pwd"))
		if method == "" || password == "" || server == "" {
			return "", "invalid"
		}
		cred := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
		u := "ss://" + cred + "@" + hostPort
		plugin := strings.TrimSpace(firstNonEmpty(kv, "plugin"))
		if plugin == "" {
			plugin = strings.TrimSpace(firstNonEmpty(kv, "plugin-name", "plugin_name"))
		}
		if pluginOpts := buildSSPluginOptsFromKV(kv); pluginOpts != "" {
			if plugin == "" {
				plugin = "v2ray-plugin"
			}
			plugin = plugin + ";" + pluginOpts
		}
		if plugin != "" {
			u += "?plugin=" + url.QueryEscape(plugin)
		}
		if fragment != "" {
			u += "#" + url.QueryEscape(fragment)
		}
		return u, "ok"
	case "trojan":
		password := strings.TrimSpace(firstNonEmpty(kv, "password", "passwd", "pwd"))
		if password == "" {
			return "", "invalid"
		}
		u := &url.URL{Scheme: "trojan", Host: hostPort, User: url.User(password)}
		q := url.Values{}
		if sni := strings.TrimSpace(firstNonEmpty(kv, "sni", "servername", "server-name", "server_name", "peer", "tls-server-name", "tls_server_name")); sni != "" {
			q.Set("sni", sni)
		}
		tlsValue := securityValueFromKV(kv)
		if tlsValue == "" && parseBoolDefault(strings.TrimSpace(firstNonEmpty(kv, "tls-enabled", "tls_enabled")), false) {
			tlsValue = "tls"
		}
		if tlsValue == "" && (q.Get("sni") != "" || parseBoolDefault(strings.TrimSpace(firstNonEmpty(kv, "skip-cert-verify", "insecure", "allow-insecure")), false)) {
			tlsValue = "tls"
		}
		if tlsValue != "" {
			q.Set("security", tlsValue)
		}
		network := normalizeTransportType(strings.TrimSpace(firstNonEmpty(kv, "network", "net", "type", "transport-type", "transport_type")))
		if network == "" {
			if strings.TrimSpace(firstNonEmpty(kv, "path", "ws-path", "ws_path", "ws-opts-path", "ws_opts_path", "transport-path", "transport_path")) != "" ||
				strings.TrimSpace(resolveHeaderHostFromKV(kv)) != "" {
				network = "ws"
			} else if strings.TrimSpace(firstNonEmpty(kv, "grpc-service-name", "grpc_service_name", "service-name", "service_name", "transport-service-name", "transport_service_name")) != "" {
				network = "grpc"
			}
		}
		if network != "" {
			q.Set("type", network)
		}
		if path := strings.TrimSpace(firstNonEmpty(kv, "path", "ws-path", "ws_path", "ws-opts-path", "ws_opts_path", "transport-path", "transport_path")); path != "" {
			q.Set("path", path)
		}
		if host := strings.TrimSpace(resolveHeaderHostFromKV(kv)); host != "" {
			q.Set("host", host)
		}
		copyKVQueryValue(kv, q, "serviceName", "serviceName", "service-name", "service_name", "grpc-service-name", "grpc_service_name", "transport-service-name", "transport_service_name")
		copyKVQueryValue(kv, q, "allowInsecure", "allow-insecure", "allow_insecure", "skip-cert-verify", "insecure")
		copyKVQueryValue(kv, q, "pbk", "pbk", "public-key", "public_key", "reality-public-key", "reality_public_key")
		copyKVQueryValue(kv, q, "sid", "sid", "short-id", "short_id", "reality-short-id", "reality_short_id")
		u.RawQuery = q.Encode()
		if fragment != "" {
			u.Fragment = fragment
		}
		return u.String(), "ok"
	case "vmess":
		uuid := strings.TrimSpace(firstNonEmpty(kv, "uuid", "id", "username", "user"))
		if uuid == "" || server == "" {
			return "", "invalid"
		}
		netType := normalizeTransportType(strings.TrimSpace(firstNonEmpty(kv, "network", "net", "type")))
		path := strings.TrimSpace(firstNonEmpty(kv, "path", "ws-path", "ws_path", "ws-opts-path", "ws_opts_path"))
		hostHeader := strings.TrimSpace(resolveHeaderHostFromKV(kv))
		grpcService := strings.TrimSpace(firstNonEmpty(kv, "serviceName", "service-name", "service_name", "grpc-service-name", "grpc_service_name"))
		if netType == "" {
			if path != "" || hostHeader != "" {
				netType = "ws"
			} else if grpcService != "" {
				netType = "grpc"
			}
		}
		obj := map[string]any{
			"v":    "2",
			"ps":   fragment,
			"add":  server,
			"port": strconv.Itoa(port),
			"id":   uuid,
			"aid":  firstNonEmpty(kv, "alterid", "alter-id", "alter_id", "aid"),
			"net":  netType,
			"type": firstNonEmpty(kv, "header", "header_type"),
			"host": hostHeader,
			"path": path,
			"tls":  vmessTLSFromKV(kv),
			"sni":  firstNonEmpty(kv, "sni", "servername", "server-name", "server_name"),
			"scy":  firstNonEmpty(kv, "cipher", "security"),
			"alpn": firstNonEmpty(kv, "alpn"),
		}
		if grpcService != "" {
			obj["serviceName"] = grpcService
		}
		clean := map[string]any{}
		for k, v := range obj {
			if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
				clean[k] = s
			}
		}
		raw, err := json.Marshal(clean)
		if err != nil {
			return "", "invalid"
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw), "ok"
	case "vless":
		uuid := strings.TrimSpace(firstNonEmpty(kv, "uuid", "id", "username", "user"))
		if uuid == "" || server == "" {
			return "", "invalid"
		}
		u := &url.URL{Scheme: "vless", Host: hostPort, User: url.User(uuid)}
		q := url.Values{}
		netType := normalizeTransportType(strings.TrimSpace(firstNonEmpty(kv, "type", "network", "net", "transport-type", "transport_type")))
		if netType == "" {
			if strings.TrimSpace(firstNonEmpty(kv, "path", "ws-path", "ws_path", "ws-opts-path", "ws_opts_path", "transport-path", "transport_path")) != "" ||
				strings.TrimSpace(resolveHeaderHostFromKV(kv)) != "" {
				netType = "ws"
			} else if strings.TrimSpace(firstNonEmpty(kv, "grpc-service-name", "grpc_service_name", "service-name", "service_name", "transport-service-name", "transport_service_name")) != "" {
				netType = "grpc"
			}
		}
		if netType != "" {
			q.Set("type", netType)
		}
		sec := securityValueFromKV(kv)
		if sec == "" && parseBoolDefault(strings.TrimSpace(firstNonEmpty(kv, "tls-enabled", "tls_enabled")), false) {
			sec = "tls"
		}
		if sec != "" {
			q.Set("security", sec)
		}
		copyKVQueryValue(kv, q, "sni", "sni", "servername", "server-name", "server_name", "peer", "tls-server-name", "tls_server_name")
		copyKVQueryValue(kv, q, "path", "path", "ws-path", "ws_path", "ws-opts-path", "ws_opts_path", "transport-path", "transport_path")
		if host := strings.TrimSpace(resolveHeaderHostFromKV(kv)); host != "" {
			q.Set("host", host)
		}
		copyKVQueryValue(kv, q, "serviceName", "serviceName", "service-name", "service_name", "grpc-service-name", "grpc_service_name", "transport-service-name", "transport_service_name")
		copyKVQueryValue(kv, q, "flow", "flow")
		copyKVQueryValue(kv, q, "pbk", "pbk", "public-key", "public_key", "reality-public-key", "reality_public_key")
		copyKVQueryValue(kv, q, "sid", "sid", "short-id", "short_id", "reality-short-id", "reality_short_id")
		copyKVQueryValue(kv, q, "alpn", "alpn")
		copyKVQueryValue(kv, q, "allowInsecure", "allow-insecure", "allow_insecure", "skip-cert-verify", "insecure")
		u.RawQuery = q.Encode()
		if fragment != "" {
			u.Fragment = fragment
		}
		return u.String(), "ok"
	case "hy2", "hysteria2":
		password := strings.TrimSpace(firstNonEmpty(kv, "password", "passwd", "pwd", "auth"))
		if password == "" || server == "" {
			return "", "invalid"
		}
		u := &url.URL{Scheme: "hy2", Host: hostPort, User: url.User(password)}
		q := url.Values{}
		copyKVQueryValue(kv, q, "sni", "sni", "servername", "server-name", "server_name", "peer")
		copyKVQueryValue(kv, q, "insecure", "insecure", "skip-cert-verify")
		copyKVQueryValue(kv, q, "obfs", "obfs")
		copyKVQueryValue(kv, q, "obfs-password", "obfs-password", "obfs_password")
		copyKVQueryValue(kv, q, "upmbps", "upmbps", "up-mbps", "up")
		copyKVQueryValue(kv, q, "downmbps", "downmbps", "down-mbps", "down")
		u.RawQuery = q.Encode()
		if fragment != "" {
			u.Fragment = fragment
		}
		return u.String(), "ok"
	case "tuic":
		uuid := strings.TrimSpace(firstNonEmpty(kv, "uuid", "id", "username", "user"))
		password := strings.TrimSpace(firstNonEmpty(kv, "password", "passwd", "pwd"))
		if uuid == "" || password == "" || server == "" {
			return "", "invalid"
		}
		u := &url.URL{Scheme: "tuic", Host: hostPort, User: url.UserPassword(uuid, password)}
		q := url.Values{}
		copyKVQueryValue(kv, q, "sni", "sni", "servername", "server-name", "server_name")
		copyKVQueryValue(kv, q, "congestion_control", "congestion_control", "congestion-controller")
		copyKVQueryValue(kv, q, "insecure", "insecure", "skip-cert-verify")
		copyKVQueryValue(kv, q, "alpn", "alpn")
		copyKVQueryValue(kv, q, "udp_relay_mode", "udp-relay-mode", "udp_relay_mode")
		u.RawQuery = q.Encode()
		if fragment != "" {
			u.Fragment = fragment
		}
		return u.String(), "ok"
	case "wireguard", "wg":
		privateKey := strings.TrimSpace(firstNonEmpty(kv, "private-key", "private_key", "privatekey"))
		publicKey := strings.TrimSpace(firstNonEmpty(kv, "public-key", "public_key", "publickey", "peer-public-key", "peer_public_key"))
		if privateKey == "" || publicKey == "" || server == "" {
			return "", "invalid"
		}
		u := &url.URL{Scheme: "wireguard", Host: hostPort, User: url.User(privateKey)}
		q := url.Values{}
		q.Set("publickey", publicKey)
		copyKVQueryValue(kv, q, "address", "address", "local-address", "local_address", "ip", "local-ip")
		copyKVQueryValue(kv, q, "mtu", "mtu")
		copyKVQueryValue(kv, q, "presharedkey", "pre-shared-key", "pre_shared_key")
		copyKVQueryValue(kv, q, "reserved", "reserved")
		u.RawQuery = q.Encode()
		if fragment != "" {
			u.Fragment = fragment
		}
		return u.String(), "ok"
	case "ssh":
		user := strings.TrimSpace(firstNonEmpty(kv, "user", "username"))
		password := strings.TrimSpace(firstNonEmpty(kv, "password", "passwd", "pwd"))
		if user == "" || server == "" {
			return "", "invalid"
		}
		u := &url.URL{Scheme: "ssh", Host: hostPort}
		if password != "" {
			u.User = url.UserPassword(user, password)
		} else {
			u.User = url.User(user)
		}
		q := url.Values{}
		copyKVQueryValue(kv, q, "private_key", "private-key", "private_key")
		u.RawQuery = q.Encode()
		if fragment != "" {
			u.Fragment = fragment
		}
		return u.String(), "ok"
	default:
		return "", "unsupported"
	}
}

func copyKVQueryValue(kv map[string]string, q url.Values, target string, fromKeys ...string) {
	if q == nil {
		return
	}
	if v := strings.TrimSpace(firstNonEmpty(kv, fromKeys...)); v != "" {
		q.Set(target, v)
	}
}

func resolveHeaderHostFromKV(kv map[string]string) string {
	if kv == nil {
		return ""
	}
	if v := strings.TrimSpace(firstNonEmpty(kv,
		"host",
		"ws-host",
		"ws_host",
		"transport-host",
		"transport_host",
		"transport-headers-host",
		"transport_headers_host",
		"ws-headers-host",
		"ws_headers_host",
		"ws-opts-headers-host",
		"ws_opts_headers_host",
	)); v != "" {
		return v
	}
	for _, key := range []string{"headers", "ws-headers", "ws_headers", "ws-opts-headers", "ws_opts_headers", "transport-headers", "transport_headers"} {
		raw := strings.TrimSpace(kv[key])
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
			raw = strings.TrimSpace(raw[1 : len(raw)-1])
		}
		inline := parseInlineKVMap(raw)
		for ik, iv := range inline {
			if normalizeKVKey(ik) == "host" && strings.TrimSpace(iv) != "" {
				return strings.TrimSpace(iv)
			}
		}
	}
	return ""
}

func buildSSPluginOptsFromKV(kv map[string]string) string {
	if kv == nil {
		return ""
	}
	if raw := strings.TrimSpace(firstNonEmpty(kv, "plugin-opts", "plugin_opts")); raw != "" {
		if strings.Contains(raw, "=") {
			return raw
		}
		// json-like plugin opts: {"mode":"websocket","host":"example.com"}
		raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(raw, "}"), "{"))
		inline := parseInlineKVMap(raw)
		if len(inline) > 0 {
			pairs := make([]string, 0, len(inline))
			keys := make([]string, 0, len(inline))
			for k := range inline {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := strings.TrimSpace(inline[k])
				if v == "" {
					continue
				}
				pairs = append(pairs, k+"="+v)
			}
			return strings.Join(pairs, ";")
		}
	}
	// flattened plugin-opts-* keys
	const prefix = "plugin-opts-"
	parts := make([]string, 0)
	keys := make([]string, 0)
	for key := range kv {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := strings.TrimSpace(kv[key])
		if v == "" {
			continue
		}
		parts = append(parts, strings.TrimPrefix(key, prefix)+"="+v)
	}
	return strings.Join(parts, ";")
}

func vmessTLSFromKV(kv map[string]string) string {
	if kv == nil {
		return ""
	}
	if sec := securityValueFromKV(kv); sec != "" {
		return sec
	}
	if parseBoolDefault(strings.TrimSpace(firstNonEmpty(kv, "tls-enabled", "tls_enabled")), false) {
		return "tls"
	}
	return ""
}

func securityValueFromKV(kv map[string]string) string {
	if kv == nil {
		return ""
	}
	for _, raw := range []string{
		strings.TrimSpace(firstNonEmpty(kv, "security")),
		strings.TrimSpace(firstNonEmpty(kv, "tls")),
	} {
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
			continue
		}
		if sec := normalizeSecurityValue(raw); sec != "" {
			return sec
		}
	}
	if parseBoolDefault(strings.TrimSpace(firstNonEmpty(kv, "tls-enabled", "tls_enabled")), false) {
		return "tls"
	}
	return ""
}

func collectIgnoredProxyFields(proxyType string, kv map[string]string) []string {
	if kv == nil {
		return nil
	}
	proxyType = strings.ToLower(strings.TrimSpace(proxyType))
	if proxyType == "" || proxyType == "anytls" {
		return nil
	}
	alwaysAllowed := map[string]struct{}{
		"name":         {},
		"label":        {},
		"tag":          {},
		"type":         {},
		"protocol":     {},
		"server":       {},
		"host":         {},
		"hostname":     {},
		"address":      {},
		"ip":           {},
		"port":         {},
		"server-port":  {},
		"server_port":  {},
		"remote-port":  {},
		"remote_port":  {},
		"ws-opts":      {},
		"ws_opts":      {},
		"grpc-opts":    {},
		"grpc_opts":    {},
		"headers":      {},
		"reality-opts": {},
		"reality_opts": {},
		"plugin-opts":  {},
		"plugin_opts":  {},
	}
	allowedByProxy := map[string]map[string]struct{}{
		"ss": {
			"cipher": {}, "method": {}, "encrypt-method": {}, "encrypt_method": {},
			"password": {}, "passwd": {}, "pwd": {},
			"plugin": {}, "plugin-name": {}, "plugin_name": {},
			"plugin-opts": {}, "plugin_opts": {},
		},
		"shadowsocks": {},
		"trojan": {
			"password": {}, "passwd": {}, "pwd": {},
			"sni": {}, "servername": {}, "server-name": {}, "server_name": {}, "peer": {},
			"security": {}, "tls": {},
			"network": {}, "net": {}, "path": {}, "ws-path": {}, "ws_path": {},
			"service-name": {}, "service_name": {}, "grpc-service-name": {}, "grpc_service_name": {},
			"allow-insecure": {}, "allow_insecure": {}, "skip-cert-verify": {}, "insecure": {},
			"public-key": {}, "public_key": {}, "pbk": {},
			"short-id": {}, "short_id": {}, "sid": {},
			"host": {}, "ws-host": {}, "ws_host": {},
		},
		"vmess": {
			"uuid": {}, "id": {}, "username": {}, "user": {},
			"alterid": {}, "alter-id": {}, "alter_id": {}, "aid": {},
			"cipher": {}, "security": {}, "tls": {},
			"sni": {}, "servername": {}, "server-name": {}, "server_name": {},
			"network": {}, "net": {}, "type": {}, "header": {}, "header_type": {},
			"path": {}, "ws-path": {}, "ws_path": {},
			"service-name": {}, "service_name": {}, "grpc-service-name": {}, "grpc_service_name": {},
			"host": {}, "ws-host": {}, "ws_host": {}, "alpn": {},
		},
		"vless": {
			"uuid": {}, "id": {}, "username": {}, "user": {},
			"type": {}, "network": {}, "net": {}, "security": {}, "tls": {},
			"sni": {}, "servername": {}, "server-name": {}, "server_name": {}, "peer": {},
			"path": {}, "ws-path": {}, "ws_path": {}, "host": {}, "ws-host": {}, "ws_host": {},
			"service-name": {}, "service_name": {}, "grpc-service-name": {}, "grpc_service_name": {},
			"flow": {}, "public-key": {}, "public_key": {}, "pbk": {},
			"short-id": {}, "short_id": {}, "sid": {}, "alpn": {},
			"allow-insecure": {}, "allow_insecure": {}, "skip-cert-verify": {}, "insecure": {},
		},
		"hy2": {
			"password": {}, "passwd": {}, "pwd": {}, "auth": {},
			"sni": {}, "servername": {}, "server-name": {}, "server_name": {}, "peer": {},
			"insecure": {}, "skip-cert-verify": {},
			"obfs": {}, "obfs-password": {}, "obfs_password": {},
			"upmbps": {}, "up-mbps": {}, "up": {}, "downmbps": {}, "down-mbps": {}, "down": {},
		},
		"hysteria2": {},
		"tuic": {
			"uuid": {}, "id": {}, "username": {}, "user": {},
			"password": {}, "passwd": {}, "pwd": {},
			"sni": {}, "servername": {}, "server-name": {}, "server_name": {},
			"insecure": {}, "skip-cert-verify": {},
			"congestion_control": {}, "congestion-controller": {},
			"alpn": {}, "udp_relay_mode": {}, "udp-relay-mode": {},
		},
		"wireguard": {
			"private-key": {}, "private_key": {}, "privatekey": {},
			"public-key": {}, "public_key": {}, "publickey": {}, "peer-public-key": {}, "peer_public_key": {},
			"address": {}, "local-address": {}, "local_address": {}, "local-ip": {},
			"mtu": {}, "pre-shared-key": {}, "pre_shared_key": {}, "reserved": {},
		},
		"wg": {},
		"ssh": {
			"user": {}, "username": {}, "password": {}, "passwd": {}, "pwd": {},
			"private-key": {}, "private_key": {}, "key": {},
		},
	}
	if allowedByProxy["shadowsocks"] == nil {
		allowedByProxy["shadowsocks"] = allowedByProxy["ss"]
	}
	if allowedByProxy["hysteria2"] == nil {
		allowedByProxy["hysteria2"] = allowedByProxy["hy2"]
	}
	if allowedByProxy["wg"] == nil {
		allowedByProxy["wg"] = allowedByProxy["wireguard"]
	}
	allowed := allowedByProxy[proxyType]
	if allowed == nil {
		return nil
	}
	ignored := make([]string, 0)
	for key := range kv {
		if _, ok := alwaysAllowed[key]; ok {
			continue
		}
		if _, ok := allowed[key]; ok {
			continue
		}
		if strings.HasPrefix(key, "ws-opts-") ||
			strings.HasPrefix(key, "ws_opts_") ||
			strings.HasPrefix(key, "grpc-opts-") ||
			strings.HasPrefix(key, "grpc_opts_") ||
			strings.HasPrefix(key, "reality-opts-") ||
			strings.HasPrefix(key, "reality_opts_") ||
			strings.HasPrefix(key, "plugin-opts-") ||
			strings.HasPrefix(key, "plugin_opts_") ||
			strings.HasPrefix(key, "headers-") ||
			strings.HasPrefix(key, "tls-") {
			continue
		}
		ignored = append(ignored, key)
	}
	sort.Strings(ignored)
	return ignored
}

func formatIgnoredFieldSummary(counter map[string]int, maxItems int) string {
	if len(counter) == 0 {
		return "-"
	}
	type kvPair struct {
		Key   string
		Count int
	}
	arr := make([]kvPair, 0, len(counter))
	for key, count := range counter {
		arr = append(arr, kvPair{Key: key, Count: count})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Count == arr[j].Count {
			return arr[i].Key < arr[j].Key
		}
		return arr[i].Count > arr[j].Count
	})
	if maxItems <= 0 || maxItems > len(arr) {
		maxItems = len(arr)
	}
	parts := make([]string, 0, maxItems)
	for i := 0; i < maxItems; i++ {
		parts = append(parts, fmt.Sprintf("%s(%d)", arr[i].Key, arr[i].Count))
	}
	if maxItems < len(arr) {
		parts = append(parts, fmt.Sprintf("+%d more", len(arr)-maxItems))
	}
	return strings.Join(parts, ", ")
}

func normalizeTransportType(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", "ws", "websocket", "grpc", "http", "h2", "http2", "tcp", "raw", "quic":
		return raw
	case "vmess", "vless", "trojan", "ss", "shadowsocks", "hysteria2", "hy2", "tuic", "wireguard", "wg", "ssh", "anytls":
		return ""
	default:
		return raw
	}
}

func normalizeSecurityValue(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", "none":
		return raw
	case "1", "true", "tls":
		return "tls"
	case "reality":
		return "reality"
	case "0", "false":
		return "none"
	default:
		return raw
	}
}

func buildAnyTLSURI(server, password, sni, egressIP, egressRule string) (string, error) {
	server = strings.TrimSpace(server)
	password = strings.TrimSpace(password)
	if server == "" || password == "" {
		return "", fmt.Errorf("server/password required")
	}
	u := &url.URL{
		Scheme: "anytls",
		Host:   server,
		User:   url.User(password),
	}
	q := url.Values{}
	if strings.TrimSpace(sni) != "" {
		q.Set("sni", strings.TrimSpace(sni))
	}
	if strings.TrimSpace(egressIP) != "" {
		q.Set("egress-ip", strings.TrimSpace(egressIP))
	}
	if strings.TrimSpace(egressRule) != "" {
		q.Set("egress-rule", strings.TrimSpace(egressRule))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func joinHostPortLoose(host string, port int) string {
	host = strings.TrimSpace(strings.Trim(host, `"'`))
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(ip.String(), strconv.Itoa(port))
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + strconv.Itoa(port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

func hasAnyTLSScheme(raw string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "anytls://")
}

func hasSupportedNodeURIScheme(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "anytls://") ||
		strings.HasPrefix(lower, "ss://") ||
		strings.HasPrefix(lower, "vmess://") ||
		strings.HasPrefix(lower, "vless://") ||
		strings.HasPrefix(lower, "trojan://") ||
		strings.HasPrefix(lower, "hy2://") ||
		strings.HasPrefix(lower, "hysteria2://") ||
		strings.HasPrefix(lower, "tuic://") ||
		strings.HasPrefix(lower, "wireguard://") ||
		strings.HasPrefix(lower, "wg://") ||
		strings.HasPrefix(lower, "ssh://") ||
		strings.HasPrefix(lower, "socks://") ||
		strings.HasPrefix(lower, "socks5://") ||
		strings.HasPrefix(lower, "singbox://") ||
		strings.HasPrefix(lower, "sing-box://") ||
		strings.HasPrefix(lower, "mihomo://")
}

func firstNonEmpty(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(values[key]); v != "" {
			return v
		}
	}
	return ""
}

func normalizeKVKey(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	key = strings.Trim(key, `"'`)
	key = strings.ReplaceAll(key, "_", "-")
	return key
}

func parseKVLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	if idx := strings.Index(line, ":"); idx > 0 {
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		value = stripYAMLInlineComment(value)
		value = strings.Trim(value, `"'`)
		return key, value, key != ""
	}
	if idx := strings.Index(line, "="); idx > 0 {
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		value = stripYAMLInlineComment(value)
		value = strings.Trim(value, `"'`)
		return key, value, key != ""
	}
	return "", "", false
}

func stripYAMLInlineComment(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	var b strings.Builder
	var quote rune
	prevIsSpace := true
	for _, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			b.WriteRune(r)
			prevIsSpace = unicode.IsSpace(r)
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			b.WriteRune(r)
			prevIsSpace = false
			continue
		}
		if r == '#' && prevIsSpace {
			break
		}
		b.WriteRune(r)
		prevIsSpace = unicode.IsSpace(r)
	}
	return strings.TrimSpace(b.String())
}

func parseInlineKVMap(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range splitCSVLoose(raw) {
		key, value, ok := parseKVLine(part)
		if !ok {
			continue
		}
		out[normalizeKVKey(key)] = value
	}
	return out
}

func splitCSVLoose(raw string) []string {
	out := make([]string, 0)
	var cur strings.Builder
	quote := byte(0)
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			cur.WriteByte(ch)
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			cur.WriteByte(ch)
			continue
		}
		if ch == ',' {
			part := strings.TrimSpace(cur.String())
			if part != "" {
				out = append(out, part)
			}
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	part := strings.TrimSpace(cur.String())
	if part != "" {
		out = append(out, part)
	}
	return out
}

func decodeBase64SubscriptionText(text string) (string, bool) {
	cleaned := strings.TrimSpace(text)
	if strings.Contains(cleaned, "://") {
		return "", false
	}
	cleaned = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', ' ':
			return -1
		default:
			return r
		}
	}, cleaned)
	if len(cleaned) < 24 {
		return "", false
	}
	for _, r := range cleaned {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' || r == '-' || r == '_' {
			continue
		}
		return "", false
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(cleaned)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(decoded))
		if text == "" {
			continue
		}
		lower := strings.ToLower(text)
		if strings.Contains(lower, "anytls://") ||
			strings.Contains(lower, "ss://") ||
			strings.Contains(lower, "vmess://") ||
			strings.Contains(lower, "vless://") ||
			strings.Contains(lower, "trojan://") ||
			strings.Contains(lower, "hy2://") ||
			strings.Contains(lower, "hysteria2://") ||
			strings.Contains(lower, "tuic://") ||
			strings.Contains(lower, "wireguard://") ||
			strings.Contains(lower, "wg://") ||
			strings.Contains(lower, "ssh://") ||
			strings.Contains(lower, "socks5://") ||
			strings.Contains(lower, "socks://") ||
			strings.Contains(lower, "singbox://") ||
			strings.Contains(lower, "mihomo://") ||
			strings.Contains(lower, "proxies:") ||
			strings.Contains(lower, "[proxy]") ||
			strings.HasPrefix(text, "{") ||
			strings.HasPrefix(text, "[") {
			return text, true
		}
	}
	return "", false
}

func dedupeSubscriptionItems(items []subscriptionNodeItem) []subscriptionNodeItem {
	if len(items) <= 1 {
		return items
	}
	out := make([]subscriptionNodeItem, 0, len(items))
	indexByURI := make(map[string]int, len(items))
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item.URI))
		if key == "" {
			continue
		}
		if idx, ok := indexByURI[key]; ok {
			if out[idx].Name == "" && strings.TrimSpace(item.Name) != "" {
				out[idx].Name = strings.TrimSpace(item.Name)
			}
			out[idx].Groups = normalizeNodeGroups(append(out[idx].Groups, item.Groups...))
			continue
		}
		item.Name = strings.TrimSpace(item.Name)
		item.Groups = normalizeNodeGroups(item.Groups)
		indexByURI[key] = len(out)
		out = append(out, item)
	}
	return out
}

func _subscriptionPayloadDebug(raw []byte) string {
	const maxLen = 256
	trimmed := strings.TrimSpace(string(bytes.TrimSpace(raw)))
	if len(trimmed) <= maxLen {
		return trimmed
	}
	return trimmed[:maxLen]
}
