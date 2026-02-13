package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var errNoRoutingHTTPProviders = errors.New("routing has no http rule providers")
var errNoRoutingProviderDue = errors.New("no routing provider needs update yet")

type routingProviderRuntimeStatus struct {
	Updating      bool
	LastAttemptAt time.Time
	LastSuccessAt time.Time
	LastError     string
}

type routingProviderUpdateItem struct {
	Name        string `json:"name"`
	Updating    bool   `json:"updating"`
	LastAttempt string `json:"last_attempt,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	Error       string `json:"error,omitempty"`
}

type routingProviderViewItem struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Behavior    string `json:"behavior,omitempty"`
	Format      string `json:"format,omitempty"`
	URL         string `json:"url,omitempty"`
	IntervalSec int    `json:"interval_sec,omitempty"`
	AutoUpdate  bool   `json:"auto_update"`
	Updating    bool   `json:"updating"`
	LastAttempt string `json:"last_attempt,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	Error       string `json:"error,omitempty"`
}

type routingGeoIPViewItem struct {
	Enabled     bool   `json:"enabled"`
	Type        string `json:"type,omitempty"`
	Updating    bool   `json:"updating"`
	LastAttempt string `json:"last_attempt,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (s *apiState) startRoutingProviderScheduler() {
	s.lock.Lock()
	if s.routingCancel != nil {
		s.routingCancel()
		s.routingCancel = nil
	}
	s.syncRoutingProviderStatusLocked()
	s.syncRoutingGeoIPStatusLocked()
	ctx, cancel := context.WithCancel(s.ctx)
	s.routingCancel = cancel
	s.lock.Unlock()

	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runRoutingProviderTick(ctx)
			}
		}
	}()
}

func (s *apiState) stopRoutingProviderScheduler() {
	s.lock.Lock()
	cancel := s.routingCancel
	s.routingCancel = nil
	s.lock.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *apiState) runRoutingProviderTick(ctx context.Context) {
	if _, _, err := s.updateRoutingProviders(ctx, nil, false); err != nil {
		if errors.Is(err, errNoRoutingHTTPProviders) || errors.Is(err, errNoRoutingProviderDue) {
			return
		}
		logrus.Warnln("[Client] auto routing provider update failed:", err)
	}
}

func (s *apiState) warmupRoutingProvidersAsync(reason string) {
	go func() {
		updated, items, err := s.updateRoutingProviders(s.ctx, nil, true)
		if err != nil {
			if errors.Is(err, errNoRoutingHTTPProviders) {
				return
			}
			logrus.Warnln("[Client] routing provider warmup failed:", reason, err)
			return
		}
		if updated {
			logrus.Infoln("[Client] routing provider warmup done:", reason, "providers=", len(items))
		}
	}()
}

func (s *apiState) handleRoutingUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Providers []string `json:"providers"`
	}
	if err := decodeJSONBody(r, &req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.maybeHandleAsyncTask(w, r, "routing_update", http.MethodPost, "/api/v1/routing/update", req, s.handleRoutingUpdate) {
		return
	}

	updated, items, err := s.updateRoutingProviders(r.Context(), req.Providers, true)
	if err != nil {
		switch {
		case errors.Is(err, errNoRoutingHTTPProviders):
			writeError(w, http.StatusBadRequest, err.Error())
		case strings.Contains(strings.ToLower(err.Error()), "not found"):
			writeError(w, http.StatusNotFound, err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"updated":   updated,
		"count":     len(items),
		"providers": items,
	})
}

func (s *apiState) handleRoutingProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.syncRoutingProviderStatusLocked()
	s.syncRoutingGeoIPStatusLocked()
	items := s.collectRoutingProviderViewsLocked()
	geoip := s.collectRoutingGeoIPViewLocked()
	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(items),
		"providers": items,
		"geoip":     geoip,
	})
}

func (s *apiState) handleRoutingProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Type     string              `json:"type"`
		Behavior string              `json:"behavior"`
		Format   string              `json:"format"`
		URL      string              `json:"url"`
		Path     string              `json:"path"`
		Header   map[string][]string `json:"header"`
		Payload  []string            `json:"payload"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.maybeHandleAsyncTask(w, r, "routing_probe", http.MethodPost, "/api/v1/routing/probe", req, s.handleRoutingProbe) {
		return
	}

	provider := clientRuleProvider{
		Type:     req.Type,
		Behavior: req.Behavior,
		Format:   req.Format,
		URL:      req.URL,
		Path:     req.Path,
		Header:   req.Header,
		Payload:  req.Payload,
	}
	if strings.TrimSpace(provider.Format) == "" {
		provider.Format = "auto"
	}
	if err := normalizeRuleProvider(&provider); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	preview, err := probeRuleProviderSource(r.Context(), provider, filepath.Dir(s.configPath))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"detected_format":     preview.Format,
		"suggested_behavior":  preview.Behavior,
		"entry_count":         preview.EntryCount,
		"mitm_host_count":     len(preview.MITMHosts),
		"mitm_hosts":          preview.MITMHosts,
		"url_reject_count":    preview.URLRejectCount,
		"sample_rules":        preview.Samples,
		"normalized_provider": provider,
	})
}

func (s *apiState) updateRoutingProviders(ctx context.Context, targetNames []string, force bool) (bool, []routingProviderUpdateItem, error) {
	s.lock.Lock()
	s.syncRoutingProviderStatusLocked()
	s.syncRoutingGeoIPStatusLocked()
	cfgRouting := cloneRoutingConfig(s.cfg.Routing)
	if cfgRouting == nil {
		s.lock.Unlock()
		return false, nil, errNoRoutingHTTPProviders
	}

	httpProviders := make(map[string]clientRuleProvider)
	for name, provider := range cfgRouting.RuleProviders {
		if strings.EqualFold(strings.TrimSpace(provider.Type), "http") {
			httpProviders[name] = provider
		}
	}
	hasGeoIPHTTP := cfgRouting.GeoIP != nil && strings.EqualFold(strings.TrimSpace(cfgRouting.GeoIP.Type), "http")
	if len(httpProviders) == 0 && !hasGeoIPHTTP {
		s.lock.Unlock()
		return false, nil, errNoRoutingHTTPProviders
	}

	now := time.Now()
	selected := make([]string, 0, len(httpProviders))
	geoIPRequestedByName := false
	if force {
		if len(targetNames) == 0 {
			for name := range httpProviders {
				selected = append(selected, name)
			}
		} else {
			seen := make(map[string]struct{}, len(targetNames))
			for _, raw := range targetNames {
				name := strings.TrimSpace(raw)
				if name == "" {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				if strings.EqualFold(name, "geoip") {
					geoIPRequestedByName = true
					seen[name] = struct{}{}
					continue
				}
				if _, ok := httpProviders[name]; !ok {
					s.lock.Unlock()
					return false, nil, fmt.Errorf("routing provider not found or not http: %s", name)
				}
				seen[name] = struct{}{}
				selected = append(selected, name)
			}
		}
	} else {
		for name, provider := range httpProviders {
			st := s.ensureRoutingProviderStatusLocked(name)
			if st.Updating {
				continue
			}
			interval := provider.IntervalSec
			if interval <= 0 {
				interval = 3600
			}
			if st.LastAttemptAt.IsZero() || now.Sub(st.LastAttemptAt) >= time.Duration(interval)*time.Second {
				selected = append(selected, name)
			}
		}
	}
	sort.Strings(selected)
	geoIPSelected := false
	if hasGeoIPHTTP {
		geoIPSelected = force && (len(targetNames) == 0 || geoIPRequestedByName || len(selected) > 0)
		if !force {
			st := s.ensureRoutingGeoIPStatusLocked()
			interval := cfgRouting.GeoIP.IntervalSec
			if interval <= 0 {
				interval = 3600
			}
			if st.LastAttemptAt.IsZero() || now.Sub(st.LastAttemptAt) >= time.Duration(interval)*time.Second {
				geoIPSelected = true
			}
			if len(selected) > 0 {
				geoIPSelected = true
			}
		}
	}
	if len(selected) == 0 && !geoIPSelected {
		items := s.collectRoutingProviderStatusLocked(nil)
		s.lock.Unlock()
		if force {
			return false, items, nil
		}
		return false, items, errNoRoutingProviderDue
	}

	for _, name := range selected {
		st := s.ensureRoutingProviderStatusLocked(name)
		st.Updating = true
		st.LastAttemptAt = now
		st.LastError = ""
	}
	if geoIPSelected {
		st := s.ensureRoutingGeoIPStatusLocked()
		st.Updating = true
		st.LastAttemptAt = now
		st.LastError = ""
	}
	configPath := s.configPath
	mitmEnabled := s.mitm != nil && s.cfg.MITM != nil && s.cfg.MITM.Enabled
	s.lock.Unlock()

	nextEngine, err := buildRoutingEngineWithOptions(ctx, cfgRouting, configPath, compileRuleOptions{
		onGeoIPResult: s.makeRoutingGeoIPCompileObserver(),
	})
	if err != nil {
		s.lock.Lock()
		canFallback := s.routing != nil
		for _, name := range selected {
			st := s.ensureRoutingProviderStatusLocked(name)
			st.Updating = false
			if canFallback {
				// Keep previous usable providers/runtime status when this refresh failed.
				st.LastError = ""
			} else {
				st.LastError = err.Error()
			}
		}
		if geoIPSelected {
			st := s.ensureRoutingGeoIPStatusLocked()
			st.Updating = false
			if !canFallback && st.LastError == "" {
				st.LastError = err.Error()
			}
		}
		items := s.collectRoutingProviderStatusLocked(selected)
		s.lock.Unlock()
		if canFallback {
			logrus.Warnln("[Client] routing provider update failed, keep previous routing rules:", err)
			return false, items, nil
		}
		return false, items, err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	// Avoid overwriting a newer runtime config when user is editing routing concurrently.
	if !sameRoutingConfig(cfgRouting, s.cfg.Routing) {
		conflictErr := fmt.Errorf("routing config changed during provider update, please retry")
		for _, name := range selected {
			st := s.ensureRoutingProviderStatusLocked(name)
			st.Updating = false
			st.LastError = conflictErr.Error()
		}
		if geoIPSelected {
			st := s.ensureRoutingGeoIPStatusLocked()
			st.Updating = false
			st.LastError = conflictErr.Error()
		}
		return false, s.collectRoutingProviderStatusLocked(selected), conflictErr
	}

	prevEngine := s.routing
	s.routing = nextEngine
	if mitmEnabled && s.cfg.MITM != nil && s.cfg.MITM.Enabled {
		if _, mitmErr := s.reconcileMITMLocked(s.cfg.MITM); mitmErr != nil {
			s.routing = prevEngine
			for _, name := range selected {
				st := s.ensureRoutingProviderStatusLocked(name)
				st.Updating = false
				st.LastError = mitmErr.Error()
			}
			if geoIPSelected {
				st := s.ensureRoutingGeoIPStatusLocked()
				st.Updating = false
				st.LastError = mitmErr.Error()
			}
			return false, s.collectRoutingProviderStatusLocked(selected), mitmErr
		}
	}

	successAt := time.Now()
	for _, name := range selected {
		st := s.ensureRoutingProviderStatusLocked(name)
		st.Updating = false
		st.LastSuccessAt = successAt
		st.LastError = ""
	}
	if geoIPSelected {
		st := s.ensureRoutingGeoIPStatusLocked()
		st.Updating = false
	}
	return true, s.collectRoutingProviderStatusLocked(selected), nil
}

func (s *apiState) makeRoutingGeoIPCompileObserver() func(geoIPCompileResult) {
	return func(result geoIPCompileResult) {
		if result.Skipped {
			return
		}
		s.lock.Lock()
		defer s.lock.Unlock()
		s.syncRoutingGeoIPStatusLocked()
		if s.cfg == nil || s.cfg.Routing == nil || s.cfg.Routing.GeoIP == nil {
			return
		}
		st := s.ensureRoutingGeoIPStatusLocked()
		st.Updating = false
		at := result.AttemptAt
		if at.IsZero() {
			at = time.Now()
		}
		if result.Attempted {
			st.LastAttemptAt = at
		}
		if result.Success {
			st.LastSuccessAt = at
			st.LastError = ""
		} else if strings.TrimSpace(result.Error) != "" {
			st.LastError = strings.TrimSpace(result.Error)
		}
	}
}

func (s *apiState) ensureRoutingProviderStatusLocked(name string) *routingProviderRuntimeStatus {
	if s.routingProviderStatus == nil {
		s.routingProviderStatus = make(map[string]*routingProviderRuntimeStatus)
	}
	if st, ok := s.routingProviderStatus[name]; ok {
		return st
	}
	st := &routingProviderRuntimeStatus{}
	s.routingProviderStatus[name] = st
	return st
}

func (s *apiState) collectRoutingProviderStatusLocked(names []string) []routingProviderUpdateItem {
	items := make([]routingProviderUpdateItem, 0)
	if s.routingProviderStatus == nil {
		return items
	}
	targets := names
	if len(targets) == 0 {
		targets = make([]string, 0, len(s.routingProviderStatus))
		for name := range s.routingProviderStatus {
			targets = append(targets, name)
		}
	}
	sort.Strings(targets)
	for _, name := range targets {
		st, ok := s.routingProviderStatus[name]
		if !ok {
			continue
		}
		item := routingProviderUpdateItem{
			Name:     name,
			Updating: st.Updating,
			Error:    st.LastError,
		}
		if !st.LastAttemptAt.IsZero() {
			item.LastAttempt = st.LastAttemptAt.Format(time.RFC3339)
		}
		if !st.LastSuccessAt.IsZero() {
			item.LastSuccess = st.LastSuccessAt.Format(time.RFC3339)
		}
		items = append(items, item)
	}
	return items
}

func (s *apiState) syncRoutingProviderStatusLocked() {
	if s.routingProviderStatus == nil {
		s.routingProviderStatus = make(map[string]*routingProviderRuntimeStatus)
	}
	valid := make(map[string]struct{})
	if s.cfg != nil && s.cfg.Routing != nil {
		for name, provider := range s.cfg.Routing.RuleProviders {
			if strings.EqualFold(strings.TrimSpace(provider.Type), "http") {
				valid[name] = struct{}{}
				_ = s.ensureRoutingProviderStatusLocked(name)
			}
		}
	}
	for name := range s.routingProviderStatus {
		if _, ok := valid[name]; !ok {
			delete(s.routingProviderStatus, name)
		}
	}
}

func (s *apiState) syncRoutingGeoIPStatusLocked() {
	if s.cfg == nil || s.cfg.Routing == nil || s.cfg.Routing.GeoIP == nil {
		s.routingGeoIPStatus = nil
		return
	}
	if s.routingGeoIPStatus == nil {
		s.routingGeoIPStatus = &routingProviderRuntimeStatus{}
	}
}

func (s *apiState) ensureRoutingGeoIPStatusLocked() *routingProviderRuntimeStatus {
	if s.routingGeoIPStatus == nil {
		s.routingGeoIPStatus = &routingProviderRuntimeStatus{}
	}
	return s.routingGeoIPStatus
}

func (s *apiState) collectRoutingGeoIPViewLocked() routingGeoIPViewItem {
	view := routingGeoIPViewItem{
		Enabled: false,
	}
	if s.cfg == nil || s.cfg.Routing == nil || s.cfg.Routing.GeoIP == nil {
		return view
	}
	view.Enabled = true
	view.Type = strings.TrimSpace(s.cfg.Routing.GeoIP.Type)
	if st := s.routingGeoIPStatus; st != nil {
		view.Updating = st.Updating
		view.Error = st.LastError
		if !st.LastAttemptAt.IsZero() {
			view.LastAttempt = st.LastAttemptAt.Format(time.RFC3339)
		}
		if !st.LastSuccessAt.IsZero() {
			view.LastSuccess = st.LastSuccessAt.Format(time.RFC3339)
		}
	}
	return view
}

func (s *apiState) collectRoutingProviderViewsLocked() []routingProviderViewItem {
	items := make([]routingProviderViewItem, 0)
	if s.cfg == nil || s.cfg.Routing == nil || len(s.cfg.Routing.RuleProviders) == 0 {
		return items
	}

	names := make([]string, 0, len(s.cfg.Routing.RuleProviders))
	for name := range s.cfg.Routing.RuleProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		provider := s.cfg.Routing.RuleProviders[name]
		view := routingProviderViewItem{
			Name:        name,
			Type:        strings.TrimSpace(provider.Type),
			Behavior:    strings.TrimSpace(provider.Behavior),
			Format:      strings.TrimSpace(provider.Format),
			URL:         strings.TrimSpace(provider.URL),
			IntervalSec: provider.IntervalSec,
		}
		if strings.EqualFold(view.Type, "http") {
			view.AutoUpdate = true
			if view.IntervalSec <= 0 {
				view.IntervalSec = 3600
			}
			if st, ok := s.routingProviderStatus[name]; ok {
				view.Updating = st.Updating
				view.Error = st.LastError
				if !st.LastAttemptAt.IsZero() {
					view.LastAttempt = st.LastAttemptAt.Format(time.RFC3339)
				}
				if !st.LastSuccessAt.IsZero() {
					view.LastSuccess = st.LastSuccessAt.Format(time.RFC3339)
				}
			}
		}
		items = append(items, view)
	}
	return items
}

func sameRoutingConfig(a, b *clientRoutingConfig) bool {
	aj, errA := json.Marshal(a)
	bj, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(aj) == string(bj)
}
