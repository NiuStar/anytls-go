package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
	xproxy "golang.org/x/net/proxy"
)

type mitmRuntime struct {
	lock   sync.Mutex
	cfg    clientMITMConfig
	socks  string
	engine *routingEngine

	listener  net.Listener
	transport *http.Transport
	ca        *mitmCA

	hostPatterns    []string
	urlReject       []*regexp.Regexp
	urlRejectHits   uint64
	urlRejectLastAt time.Time
	urlRejectLast   string
	urlRejectLastRe string
	urlRejectByRe   map[string]uint64
	urlRejectByReAt map[string]time.Time
	certCache       map[string]*tls.Certificate
	certSelectLogAt map[string]time.Time

	connLock  sync.Mutex
	activeCon map[net.Conn]struct{}
	closed    bool
}

type mitmCA struct {
	cert       *x509.Certificate
	key        *rsa.PrivateKey
	certPEMRaw []byte
}

type mitmURLRejectRuleHit struct {
	Rule   string
	Hits   uint64
	LastAt time.Time
}

func startMITMRuntime(ctx context.Context, cfg clientMITMConfig, socksListen string, engine *routingEngine) (*mitmRuntime, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := normalizeMITMConfig(&cfg); err != nil {
		return nil, err
	}

	socksDialer, err := xproxy.SOCKS5("tcp", socksListen, nil, xproxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("create mitm socks dialer failed: %w", err)
	}
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		type contextDialer interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		}
		if d, ok := socksDialer.(contextDialer); ok {
			return d.DialContext(ctx, network, address)
		}
		return socksDialer.Dial(network, address)
	}

	ca, err := loadOrCreateMITMCA(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		return nil, err
	}

	hostPatterns, urlReject, err := buildMITMRuntimeRules(cfg, engine)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen mitm proxy failed: %w", err)
	}

	runtime := &mitmRuntime{
		cfg:             cfg,
		socks:           socksListen,
		engine:          engine,
		listener:        listener,
		ca:              ca,
		hostPatterns:    hostPatterns,
		urlReject:       urlReject,
		urlRejectByRe:   make(map[string]uint64),
		urlRejectByReAt: make(map[string]time.Time),
		certCache:       make(map[string]*tls.Certificate),
		certSelectLogAt: make(map[string]time.Time),
		activeCon:       make(map[net.Conn]struct{}),
		transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialContext,
			DisableCompression:  true,
			TLSHandshakeTimeout: 12 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.AllowInsecure,
			},
			ForceAttemptHTTP2: false,
		},
	}

	go runtime.serve(ctx)
	return runtime, nil
}

func (m *mitmRuntime) Close() error {
	if m == nil {
		return nil
	}
	m.lock.Lock()
	listener := m.listener
	m.listener = nil
	transport := m.transport
	m.lock.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	if transport != nil {
		transport.CloseIdleConnections()
	}

	var toClose []net.Conn
	m.connLock.Lock()
	if !m.closed {
		m.closed = true
		toClose = make([]net.Conn, 0, len(m.activeCon))
		for conn := range m.activeCon {
			toClose = append(toClose, conn)
		}
		m.activeCon = make(map[net.Conn]struct{})
	}
	m.connLock.Unlock()

	for _, conn := range toClose {
		_ = conn.Close()
	}
	return nil
}

func (m *mitmRuntime) ResetConnections(reason string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	transport := m.transport
	m.lock.Unlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}

	m.connLock.Lock()
	conns := make([]net.Conn, 0, len(m.activeCon))
	for conn := range m.activeCon {
		conns = append(conns, conn)
	}
	m.connLock.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
	if len(conns) > 0 {
		logrus.Warnf("[Client] mitm active connections reset: reason=%s closed=%d", strings.TrimSpace(reason), len(conns))
	}
}

func (m *mitmRuntime) reusableWith(next clientMITMConfig, socksListen string) bool {
	if m == nil {
		return false
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.listener == nil || m.transport == nil {
		return false
	}
	return strings.TrimSpace(m.socks) == strings.TrimSpace(socksListen) &&
		strings.TrimSpace(m.cfg.Listen) == strings.TrimSpace(next.Listen) &&
		strings.TrimSpace(m.cfg.CACertPath) == strings.TrimSpace(next.CACertPath) &&
		strings.TrimSpace(m.cfg.CAKeyPath) == strings.TrimSpace(next.CAKeyPath) &&
		m.cfg.AllowInsecure == next.AllowInsecure
}

func (m *mitmRuntime) refreshDynamicRules(cfg clientMITMConfig, engine *routingEngine) error {
	if m == nil {
		return nil
	}
	hostPatterns, urlReject, err := buildMITMRuntimeRules(cfg, engine)
	if err != nil {
		return err
	}
	m.lock.Lock()
	m.cfg.Hosts = append([]string(nil), cfg.Hosts...)
	m.cfg.URLReject = append([]string(nil), cfg.URLReject...)
	m.cfg.DoHDoT = cloneMITMDoHDoTConfig(cfg.DoHDoT)
	m.engine = engine
	m.hostPatterns = hostPatterns
	m.urlReject = urlReject
	active := make(map[string]struct{}, len(urlReject))
	for _, re := range urlReject {
		active[re.String()] = struct{}{}
	}
	nextByRe := make(map[string]uint64, len(active))
	nextByReAt := make(map[string]time.Time, len(active))
	for rule, count := range m.urlRejectByRe {
		if _, ok := active[rule]; ok {
			nextByRe[rule] = count
		}
	}
	for rule, at := range m.urlRejectByReAt {
		if _, ok := active[rule]; ok {
			nextByReAt[rule] = at
		}
	}
	m.urlRejectByRe = nextByRe
	m.urlRejectByReAt = nextByReAt
	if _, ok := active[m.urlRejectLastRe]; !ok {
		m.urlRejectLastRe = ""
	}
	m.lock.Unlock()
	return nil
}

func (m *mitmRuntime) ListenAddr() string {
	if m == nil {
		return ""
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.listener == nil {
		return ""
	}
	return m.listener.Addr().String()
}

func (m *mitmRuntime) HostCount() int {
	if m == nil {
		return 0
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	return len(m.hostPatterns)
}

func (m *mitmRuntime) URLRejectCount() int {
	if m == nil {
		return 0
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	return len(m.urlReject)
}

func (m *mitmRuntime) URLRejectStats() (count uint64, lastAt time.Time, lastURL, lastRule string, top []mitmURLRejectRuleHit) {
	if m == nil {
		return 0, time.Time{}, "", "", nil
	}
	m.lock.Lock()
	count = m.urlRejectHits
	lastAt = m.urlRejectLastAt
	lastURL = m.urlRejectLast
	lastRule = m.urlRejectLastRe
	byRule := make(map[string]uint64, len(m.urlRejectByRe))
	byRuleAt := make(map[string]time.Time, len(m.urlRejectByReAt))
	for rule, hits := range m.urlRejectByRe {
		byRule[rule] = hits
	}
	for rule, at := range m.urlRejectByReAt {
		byRuleAt[rule] = at
	}
	m.lock.Unlock()

	top = make([]mitmURLRejectRuleHit, 0, len(byRule))
	for rule, hits := range byRule {
		top = append(top, mitmURLRejectRuleHit{
			Rule:   rule,
			Hits:   hits,
			LastAt: byRuleAt[rule],
		})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Hits == top[j].Hits {
			return top[i].Rule < top[j].Rule
		}
		return top[i].Hits > top[j].Hits
	})
	if len(top) > 5 {
		top = top[:5]
	}
	return count, lastAt, lastURL, lastRule, top
}

func (m *mitmRuntime) CAPEM() []byte {
	if m == nil || m.ca == nil || len(m.ca.certPEMRaw) == 0 {
		return nil
	}
	out := make([]byte, len(m.ca.certPEMRaw))
	copy(out, m.ca.certPEMRaw)
	return out
}

func (m *mitmRuntime) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = m.Close()
	}()

	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			return
		}
		if !m.trackConn(conn) {
			_ = conn.Close()
			return
		}
		go m.handleClient(ctx, conn)
	}
}

func (m *mitmRuntime) HandleDoHDoTConnection(
	ctx context.Context,
	conn net.Conn,
	metadata M.Metadata,
	hintedHosts []string,
	hijacker *dnsHijacker,
	cfg clientMITMDoHDoTConfig,
) (bool, error) {
	if m == nil || conn == nil || hijacker == nil || !cfg.Enabled {
		return false, nil
	}
	port := metadata.Destination.Port
	switch port {
	case 853:
		if !matchDoTHijackTarget(metadata.Destination, hintedHosts, cfg.DoTHosts) {
			return false, nil
		}
		return true, m.handleDoTTLSConnection(ctx, conn, metadata, hintedHosts, hijacker)
	case 443:
		if !matchDoHHijackTarget(metadata.Destination, hintedHosts, cfg.DoHHosts) {
			return false, nil
		}
		return true, m.handleDoHHTTPSConnection(ctx, conn, metadata, hintedHosts, hijacker)
	default:
		return false, nil
	}
}

func (m *mitmRuntime) HandleTransparentHTTPSConnection(
	ctx context.Context,
	clientConn net.Conn,
	metadata M.Metadata,
	hintedHosts []string,
) (bool, error) {
	if m == nil || clientConn == nil {
		return false, nil
	}
	if metadata.Destination.Port != 443 {
		return false, nil
	}

	targetHost := ""
	candidates := collectMITMCandidateHosts(metadata.Destination, hintedHosts)
	for _, host := range candidates {
		if net.ParseIP(host) != nil {
			continue
		}
		if m.matchMITMHost(host) {
			targetHost = host
			break
		}
	}
	if targetHost == "" {
		return false, nil
	}
	targetPort := metadata.Destination.Port
	if targetPort == 0 {
		targetPort = 443
	}
	defaultHost := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))

	if !m.trackConn(clientConn) {
		return true, nil
	}
	defer m.untrackConn(clientConn)

	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			var sni string
			if hello != nil {
				sni = hello.ServerName
			}
			host := selectMITMCertHostForTransparent(targetHost, sni)
			if host == "" {
				host = targetHost
			}
			m.logMITMCertSelection("transparent", "target_host", targetHost, sni, host)
			return m.getOrIssueLeafCert(host)
		},
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return true, err
	}

	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return true, nil
			}
			return true, err
		}
		if err := m.forwardHTTPRequest(tlsConn, req, "https", defaultHost); err != nil {
			return true, err
		}
		if req.Close {
			return true, nil
		}
	}
}

func (m *mitmRuntime) handleClient(ctx context.Context, conn net.Conn) {
	defer m.untrackConn(conn)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if strings.EqualFold(req.Method, http.MethodConnect) {
			m.handleConnect(ctx, conn, req)
			return
		}
		if err := m.forwardHTTPRequest(conn, req, "http", req.Host); err != nil {
			return
		}
		if req.Close {
			return
		}
	}
}

func (m *mitmRuntime) trackConn(conn net.Conn) bool {
	if m == nil || conn == nil {
		return false
	}
	m.connLock.Lock()
	defer m.connLock.Unlock()
	if m.closed {
		return false
	}
	m.activeCon[conn] = struct{}{}
	return true
}

func (m *mitmRuntime) untrackConn(conn net.Conn) {
	if m == nil || conn == nil {
		return
	}
	m.connLock.Lock()
	delete(m.activeCon, conn)
	m.connLock.Unlock()
}

func buildMITMRuntimeRules(cfg clientMITMConfig, engine *routingEngine) ([]string, []*regexp.Regexp, error) {
	urlReject := make([]*regexp.Regexp, 0, len(cfg.URLReject)+8)
	for _, pattern := range cfg.URLReject {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, nil, fmt.Errorf("compile mitm url_reject %q failed: %w", pattern, err)
		}
		urlReject = append(urlReject, re)
	}
	if engine != nil && len(engine.mitmURLRejectRegex) > 0 {
		urlReject = append(urlReject, engine.mitmURLRejectRegex...)
	}

	hostPatterns := make([]string, 0, len(cfg.Hosts)+8)
	hostPatterns = append(hostPatterns, cfg.Hosts...)
	if engine != nil && len(engine.mitmHosts) > 0 {
		hostPatterns = append(hostPatterns, engine.mitmHosts...)
	}
	hostPatterns = dedupAndSortStrings(hostPatterns)
	return hostPatterns, urlReject, nil
}

func (m *mitmRuntime) handleDoTTLSConnection(
	ctx context.Context,
	clientConn net.Conn,
	metadata M.Metadata,
	hintedHosts []string,
	hijacker *dnsHijacker,
) error {
	if hijacker == nil {
		return nil
	}
	targetHost := pickMITMTargetHost(metadata.Destination, hintedHosts)
	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			var sni string
			if hello != nil {
				sni = hello.ServerName
			}
			host := selectMITMCertHostForTransparent(targetHost, sni)
			if host == "" {
				host = "localhost"
			}
			m.logMITMCertSelection("dot", "target_host", targetHost, sni, host)
			return m.getOrIssueLeafCert(host)
		},
		MinVersion: tls.VersionTLS12,
	})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	var lenBuf [2]byte
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		_ = tlsConn.SetReadDeadline(time.Now().Add(3 * time.Minute))
		if _, err := io.ReadFull(tlsConn, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen <= 0 || msgLen > 65535 {
			return errors.New("invalid dot message length")
		}

		request := make([]byte, msgLen)
		if _, err := io.ReadFull(tlsConn, request); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}

		response, err := hijacker.exchangeTCP(ctx, metadata.Destination, request)
		if err != nil {
			return err
		}
		hijacker.captureResponse(response)
		if len(response) > 65535 {
			return errors.New("dot response too large")
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(response)))
		if _, err := tlsConn.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := tlsConn.Write(response); err != nil {
			return err
		}
	}
}

func (m *mitmRuntime) handleDoHHTTPSConnection(
	ctx context.Context,
	clientConn net.Conn,
	metadata M.Metadata,
	hintedHosts []string,
	hijacker *dnsHijacker,
) error {
	if hijacker == nil {
		return nil
	}
	targetHost := pickMITMTargetHost(metadata.Destination, hintedHosts)
	if targetHost == "" {
		return nil
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			var sni string
			if hello != nil {
				sni = hello.ServerName
			}
			host := selectMITMCertHostForTransparent(targetHost, sni)
			if host == "" {
				host = "localhost"
			}
			m.logMITMCertSelection("doh", "target_host", targetHost, sni, host)
			return m.getOrIssueLeafCert(host)
		},
		MinVersion: tls.VersionTLS12,
	})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	reader := bufio.NewReader(tlsConn)
	defaultHost := net.JoinHostPort(targetHost, "443")
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		handled, err := m.tryHandleDoHRequest(ctx, tlsConn, req, metadata.Destination, hijacker)
		if err != nil {
			return err
		}
		if !handled {
			if err := m.forwardHTTPRequest(tlsConn, req, "https", defaultHost); err != nil {
				return err
			}
		}
		if req.Close {
			return nil
		}
	}
}

func (m *mitmRuntime) tryHandleDoHRequest(
	ctx context.Context,
	conn net.Conn,
	req *http.Request,
	destination M.Socksaddr,
	hijacker *dnsHijacker,
) (bool, error) {
	if req == nil || hijacker == nil {
		return false, nil
	}
	payload, isDoH, err := decodeDoHRequestMessage(req)
	if !isDoH {
		return false, nil
	}
	defer req.Body.Close()
	if err != nil {
		return true, writeHTTPStatus(conn, http.StatusBadRequest, err.Error())
	}
	respPayload, err := hijacker.exchange(ctx, destination, payload)
	if err != nil {
		return true, writeHTTPStatus(conn, http.StatusBadGateway, err.Error())
	}
	hijacker.captureResponse(respPayload)
	return true, writeDoHHTTPResponse(conn, req, respPayload)
}

func (m *mitmRuntime) handleConnect(ctx context.Context, clientConn net.Conn, req *http.Request) {
	targetHost, targetPort, err := splitHostPortWithDefault(req.Host, "443")
	if err != nil {
		_ = writeHTTPStatus(clientConn, http.StatusBadRequest, "bad connect target")
		return
	}
	targetAddr := net.JoinHostPort(targetHost, targetPort)

	if !m.matchMITMHost(targetHost) {
		m.tunnelConnect(ctx, clientConn, targetAddr)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			var sni string
			if hello != nil {
				sni = hello.ServerName
			}
			host := selectMITMCertHostForConnect(targetHost, sni)
			m.logMITMCertSelection("connect", "connect_host", targetHost, sni, host)
			return m.getOrIssueLeafCert(host)
		},
		MinVersion: tls.VersionTLS12,
	})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	reader := bufio.NewReader(tlsConn)
	for {
		r, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if err := m.forwardHTTPRequest(tlsConn, r, "https", targetAddr); err != nil {
			return
		}
		if r.Close {
			return
		}
	}
}

func decodeDoHRequestMessage(req *http.Request) ([]byte, bool, error) {
	if req == nil || req.URL == nil {
		return nil, false, nil
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	path := strings.ToLower(strings.TrimSpace(req.URL.Path))
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	dnsParam := strings.TrimSpace(req.URL.Query().Get("dns"))

	likelyDoH := dnsParam != "" ||
		strings.HasSuffix(path, "/dns-query") ||
		strings.Contains(path, "dns-query") ||
		strings.Contains(contentType, "application/dns-message")
	if !likelyDoH {
		return nil, false, nil
	}

	switch method {
	case http.MethodGet:
		if dnsParam == "" {
			return nil, true, fmt.Errorf("doh GET missing dns param")
		}
		msg, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			msg, err = base64.URLEncoding.DecodeString(dnsParam)
		}
		if err != nil {
			return nil, true, fmt.Errorf("invalid doh dns param: %w", err)
		}
		if len(msg) == 0 {
			return nil, true, fmt.Errorf("empty doh dns payload")
		}
		return msg, true, nil
	case http.MethodPost:
		raw, err := io.ReadAll(io.LimitReader(req.Body, 2*1024*1024))
		if err != nil {
			return nil, true, fmt.Errorf("read doh body failed: %w", err)
		}
		if len(raw) == 0 {
			return nil, true, fmt.Errorf("empty doh request body")
		}
		return raw, true, nil
	default:
		return nil, true, fmt.Errorf("unsupported doh method: %s", method)
	}
}

func writeDoHHTTPResponse(conn net.Conn, req *http.Request, payload []byte) error {
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(payload)),
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(payload)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "application/dns-message")
	resp.Header.Set("Cache-Control", "no-store")
	if req != nil && req.Close {
		resp.Close = true
		resp.Header.Set("Connection", "close")
	}
	return resp.Write(conn)
}

func (m *mitmRuntime) tunnelConnect(ctx context.Context, clientConn net.Conn, targetAddr string) {
	upstream, err := m.transport.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		_ = writeHTTPStatus(clientConn, http.StatusBadGateway, "upstream dial failed")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstream)
		done <- struct{}{}
	}()
	<-done
}

func matchDoHHijackTarget(destination M.Socksaddr, hintedHosts, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	candidates := collectMITMCandidateHosts(destination, hintedHosts)
	if len(candidates) == 0 {
		return false
	}
	for _, host := range candidates {
		if matchMITMHostPatterns(host, patterns) {
			return true
		}
	}
	return false
}

func matchDoTHijackTarget(destination M.Socksaddr, hintedHosts, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	candidates := collectMITMCandidateHosts(destination, hintedHosts)
	if len(candidates) == 0 {
		return false
	}
	for _, host := range candidates {
		if matchMITMHostPatterns(host, patterns) {
			return true
		}
	}
	return false
}

func collectMITMCandidateHosts(destination M.Socksaddr, hintedHosts []string) []string {
	out := make([]string, 0, len(hintedHosts)+2)
	if destination.IsFqdn() {
		out = appendNormalizedUniqueHost(out, destination.Fqdn)
	}
	if destination.IsIP() {
		out = appendNormalizedUniqueHost(out, destination.Addr.Unmap().String())
	}
	for _, item := range hintedHosts {
		out = appendNormalizedUniqueHost(out, item)
	}
	return out
}

func pickMITMTargetHost(destination M.Socksaddr, hintedHosts []string) string {
	candidates := collectMITMCandidateHosts(destination, hintedHosts)
	for _, host := range candidates {
		if net.ParseIP(host) != nil {
			continue
		}
		return host
	}
	for _, host := range candidates {
		if host != "" {
			return host
		}
	}
	return ""
}

func appendNormalizedUniqueHost(base []string, value string) []string {
	value = normalizeHost(strings.TrimSpace(value))
	if value == "" {
		return base
	}
	for _, item := range base {
		if item == value {
			return base
		}
	}
	return append(base, value)
}

func matchMITMHostPatterns(host string, patterns []string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, pattern := range patterns {
		if mitmHostMatch(pattern, host) {
			return true
		}
	}
	return false
}

func (m *mitmRuntime) forwardHTTPRequest(dst net.Conn, req *http.Request, defaultScheme, defaultHost string) error {
	defer req.Body.Close()
	fullURL := requestFullURL(req, defaultScheme, defaultHost)
	if matched, rule := m.matchURLReject(fullURL); matched {
		m.recordURLRejectHit(fullURL, rule)
		logrus.Debugf("[Client] mitm url-rewrite reject: url=%s", fullURL)
		return writeHTTPStatus(dst, http.StatusForbidden, "blocked by mitm url rewrite")
	}

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	if outReq.URL == nil || !outReq.URL.IsAbs() {
		outReq.URL = mustBuildURL(defaultScheme, defaultHost, req.URL)
	}
	outReq.Host = req.Host
	sanitizeForwardHeaders(outReq.Header)
	resp, err := m.transport.RoundTrip(outReq)
	if err != nil {
		logrus.Warnf("[Client] mitm upstream roundtrip failed: host=%s method=%s err=%v", outReq.Host, outReq.Method, err)
		return writeHTTPStatus(dst, http.StatusBadGateway, err.Error())
	}
	defer resp.Body.Close()
	sanitizeForwardHeaders(resp.Header)
	// Upstream may terminate early; avoid forwarding stale Content-Length to prevent
	// client-side ERR_CONTENT_LENGTH_MISMATCH on partial responses.
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.TransferEncoding = nil
	err = resp.Write(dst)
	if err != nil {
		logrus.Warnf("[Client] mitm write response failed: host=%s method=%s status=%d err=%v", outReq.Host, outReq.Method, resp.StatusCode, err)
		return err
	}
	return nil
}

func sanitizeForwardHeaders(h http.Header) {
	if len(h) == 0 {
		return
	}
	removeConnectionTokenHeaders(h)
	// RFC 7230 hop-by-hop headers.
	h.Del("Connection")
	h.Del("Proxy-Connection")
	h.Del("Keep-Alive")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("TE")
	h.Del("Trailer")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
}

func removeConnectionTokenHeaders(h http.Header) {
	for _, raw := range h.Values("Connection") {
		for _, token := range strings.Split(raw, ",") {
			name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(token))
			if name == "" {
				continue
			}
			h.Del(name)
		}
	}
}

func mustBuildURL(scheme, host string, in *url.URL) *url.URL {
	u := &url.URL{Scheme: scheme, Host: host}
	if in == nil {
		u.Path = "/"
		return u
	}
	u.Path = in.Path
	u.RawPath = in.RawPath
	u.RawQuery = in.RawQuery
	u.Fragment = in.Fragment
	if u.Path == "" {
		u.Path = "/"
	}
	return u
}

func requestFullURL(req *http.Request, defaultScheme, defaultHost string) string {
	if req == nil {
		return ""
	}
	if req.URL != nil && req.URL.IsAbs() {
		return req.URL.String()
	}
	u := mustBuildURL(defaultScheme, defaultHost, req.URL)
	return u.String()
}

func (m *mitmRuntime) matchURLReject(fullURL string) (bool, string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, re := range m.urlReject {
		if re.MatchString(fullURL) {
			return true, re.String()
		}
	}
	return false, ""
}

func (m *mitmRuntime) recordURLRejectHit(fullURL, rule string) {
	if m == nil {
		return
	}
	fullURL = strings.TrimSpace(fullURL)
	if len(fullURL) > 256 {
		fullURL = fullURL[:256] + "..."
	}
	m.lock.Lock()
	m.urlRejectHits++
	m.urlRejectLastAt = time.Now()
	m.urlRejectLast = fullURL
	m.urlRejectLastRe = strings.TrimSpace(rule)
	if m.urlRejectByRe == nil {
		m.urlRejectByRe = make(map[string]uint64)
	}
	if m.urlRejectByReAt == nil {
		m.urlRejectByReAt = make(map[string]time.Time)
	}
	if m.urlRejectLastRe != "" {
		m.urlRejectByRe[m.urlRejectLastRe]++
		m.urlRejectByReAt[m.urlRejectLastRe] = m.urlRejectLastAt
	}
	m.lock.Unlock()
}

func (m *mitmRuntime) matchMITMHost(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, pattern := range m.hostPatterns {
		if mitmHostMatch(pattern, host) {
			return true
		}
	}
	return false
}

func (m *mitmRuntime) ShouldBlockQUIC(destination M.Socksaddr, hintedHosts []string) bool {
	if m == nil {
		return false
	}
	if destination.Port != 443 {
		return false
	}
	candidates := collectMITMCandidateHosts(destination, hintedHosts)
	if len(candidates) == 0 {
		return false
	}
	m.lock.Lock()
	patterns := append([]string(nil), m.hostPatterns...)
	m.lock.Unlock()
	if len(patterns) == 0 {
		return false
	}
	for _, host := range candidates {
		if matchMITMHostPatterns(host, patterns) {
			return true
		}
	}
	return false
}

func mitmHostMatch(pattern, host string) bool {
	pattern = normalizeMITMHostPattern(pattern)
	if pattern == "" || host == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return false
}

func splitHostPortWithDefault(raw, defaultPort string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("empty address")
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		host = strings.Trim(host, "[]")
		if host == "" {
			return "", "", fmt.Errorf("empty host")
		}
		return host, port, nil
	}
	host := strings.Trim(raw, "[]")
	if host == "" {
		return "", "", fmt.Errorf("empty host")
	}
	return host, defaultPort, nil
}

func canonicalMITMCertHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	} else if strings.Count(raw, ":") == 1 {
		if idx := strings.LastIndex(raw, ":"); idx > 0 && idx < len(raw)-1 {
			if _, perr := net.LookupPort("tcp", raw[idx+1:]); perr == nil {
				raw = raw[:idx]
			}
		}
	}
	raw = strings.TrimSpace(strings.Trim(raw, "[]"))
	return normalizeHost(raw)
}

func selectMITMCertHostForConnect(connectHost, sniHost string) string {
	connectHost = canonicalMITMCertHost(connectHost)
	sniHost = canonicalMITMCertHost(sniHost)

	if sniHost == "" {
		return connectHost
	}
	// In CONNECT MITM, certificate must match what client validates.
	// Prefer SNI whenever present; fallback to CONNECT host only if SNI is absent.
	return sniHost
}

func selectMITMCertHostForTransparent(targetHost, sniHost string) string {
	targetHost = canonicalMITMCertHost(targetHost)
	sniHost = canonicalMITMCertHost(sniHost)
	if sniHost != "" {
		return sniHost
	}
	return targetHost
}

func writeHTTPStatus(w io.Writer, code int, msg string) error {
	if strings.TrimSpace(msg) == "" {
		msg = http.StatusText(code)
	}
	body := []byte(msg + "\n")
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", code, http.StatusText(code), len(body), body)
	return err
}

func (m *mitmRuntime) getOrIssueLeafCert(host string) (*tls.Certificate, error) {
	host = canonicalMITMCertHost(host)
	if host == "" {
		return nil, errors.New("empty sni host")
	}
	m.lock.Lock()
	if cert, ok := m.certCache[host]; ok {
		m.lock.Unlock()
		logrus.Debugf("[Client] mitm cert cache hit: final_cert_host=%s", host)
		return cert, nil
	}
	m.lock.Unlock()

	logrus.Infof("[Client] mitm cert issuing: final_cert_host=%s", host)
	cert, err := issueMITMLeafCert(m.ca, host)
	if err != nil {
		logrus.Warnf("[Client] mitm cert issue failed: final_cert_host=%s err=%v", host, err)
		return nil, err
	}
	m.lock.Lock()
	m.certCache[host] = cert
	m.lock.Unlock()
	logrus.Infof("[Client] mitm cert issued: final_cert_host=%s", host)
	return cert, nil
}

func (m *mitmRuntime) logMITMCertSelection(mode, targetKey, targetHost, sniHost, finalCertHost string) {
	targetHost = canonicalMITMCertHost(targetHost)
	sniHost = canonicalMITMCertHost(sniHost)
	finalCertHost = canonicalMITMCertHost(finalCertHost)
	if finalCertHost == "" {
		finalCertHost = "localhost"
	}
	if targetHost == sniHost && sniHost == finalCertHost {
		return
	}
	if targetKey == "" {
		targetKey = "target_host"
	}
	logKey := strings.Join([]string{mode, targetKey, targetHost, sniHost, finalCertHost}, "|")
	now := time.Now()
	m.lock.Lock()
	last := m.certSelectLogAt[logKey]
	if !last.IsZero() && now.Sub(last) < 30*time.Second {
		m.lock.Unlock()
		return
	}
	m.certSelectLogAt[logKey] = now
	m.lock.Unlock()
	logrus.Warnf(
		"[Client] mitm cert selection: mode=%s %s=%s sni=%s final_cert_host=%s",
		mode,
		targetKey,
		targetHost,
		sniHost,
		finalCertHost,
	)
}

func loadOrCreateMITMCA(certPath, keyPath string) (*mitmCA, error) {
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := parseMITMCA(certPEM, keyPEM)
		if err == nil {
			return ca, nil
		}
	}

	ca, certPEMRaw, keyPEMRaw, err := generateMITMCA()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEMRaw, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEMRaw, 0600); err != nil {
		return nil, err
	}
	ca.certPEMRaw = certPEMRaw
	return ca, nil
}

func parseMITMCA(certPEM, keyPEM []byte) (*mitmCA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("ca certificate is not CA")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid ca key pem")
	}
	var key *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("ca key is not rsa private key")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported ca key type %s", keyBlock.Type)
	}
	if err != nil {
		return nil, err
	}
	return &mitmCA{cert: cert, key: key, certPEMRaw: certPEM}, nil
}

func generateMITMCA() (*mitmCA, []byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AnyTLS MITM Root CA",
			Organization: []string{"AnyTLS"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return &mitmCA{cert: cert, key: key, certPEMRaw: certPEM}, certPEM, keyPEM, nil
}

func issueMITMLeafCert(ca *mitmCA, host string) (*tls.Certificate, error) {
	if ca == nil || ca.cert == nil || ca.key == nil {
		return nil, fmt.Errorf("mitm ca not initialized")
	}
	host = canonicalMITMCertHost(host)
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.DNSNames = nil
		template.IPAddresses = []net.IP{ip}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
