package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type subscriptionConfig struct {
	PublicIP string `json:"public_ip"`
	Listen   string `json:"listen"`
	Token    string `json:"token"`
	NodeName string `json:"node_name"`
}

// Restrict advertised addresses to public unicast. No DNS or interface guessing.
func subscriptionPublicIP(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() || s != a.String() || !isPublicIP(s) {
		return false
	}
	blocked := []string{"0.0.0.0/8", "192.0.0.0/24", "192.88.99.0/24", "240.0.0.0/4", "2001::/23", "2002::/16", "3fff::/20"}
	for _, p := range blocked {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return a.Is4() || netip.MustParsePrefix("2000::/3").Contains(a)
}
func validateSubscriptionConfig(c subscriptionConfig) error {
	if !subscriptionPublicIP(c.PublicIP) {
		return errors.New("subscription requires a canonical public numeric IP; set --public-ip")
	}
	if err := validateListen(c.Listen); err != nil {
		return errors.New("invalid subscription listen address")
	}
	host, port, _ := net.SplitHostPort(c.Listen)
	p, err := strconv.Atoi(port)
	if err != nil || strconv.Itoa(p) != port {
		return errors.New("subscription port must use canonical decimal spelling")
	}
	if host != "" {
		if a, err := netip.ParseAddr(host); err != nil || a.Zone() != "" {
			return errors.New("subscription listen host must be numeric")
		}
	}
	b, err := base64.RawURLEncoding.DecodeString(c.Token)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != c.Token {
		return errors.New("invalid subscription token")
	}
	if c.NodeName == "" || len(c.NodeName) > 256 || hasControlChars(c.NodeName) {
		return errors.New("invalid subscription node name")
	}
	return nil
}
func loadSubscriptionConfig(path string) (subscriptionConfig, error) {
	var c subscriptionConfig
	info, err := os.Lstat(path)
	if err != nil {
		return c, errors.New("cannot read subscription config")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 16384 {
		return c, errors.New("subscription config must be a regular private 0600 file (max 16 KiB)")
	}
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot open subscription config")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return c, errors.New("cannot read subscription config")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid subscription config JSON")
	}
	return c, validateSubscriptionConfig(c)
}
func saveSubscriptionConfig(path string, c subscriptionConfig) error {
	if err := validateSubscriptionConfig(c); err != nil {
		return err
	}
	if i, err := os.Lstat(path); err == nil && (!i.Mode().IsRegular() || i.Mode().Perm() != 0600) {
		return errors.New("refusing unsafe subscription config target")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".subscription-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(raw, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func subscriptionURL(c subscriptionConfig, pin [32]byte) string {
	_, port, _ := net.SplitHostPort(c.Listen)
	host := c.PublicIP
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "443" {
		host = net.JoinHostPort(c.PublicIP, port)
	}
	return "https://" + host + "/subscribe/" + c.Token + "#anytls-cert-sha256=" + hex.EncodeToString(pin[:])
}
func subscriptionHandler(c subscriptionConfig, tc *tls.Config, listen, password string) (http.Handler, []byte, [32]byte, error) {
	var zero [32]byte
	if tc == nil || tc.GetCertificate != nil || tc.GetConfigForClient != nil || len(tc.Certificates) != 1 || len(tc.Certificates[0].Certificate) == 0 {
		return nil, nil, zero, errors.New("subscription requires one persistent active certificate; dynamic CA issuance is not supported")
	}
	leaf, err := x509.ParseCertificate(tc.Certificates[0].Certificate[0])
	if err != nil {
		return nil, nil, zero, errors.New("invalid active subscription certificate")
	}
	portText, err := listenPort(listen)
	if err != nil {
		return nil, nil, zero, err
	}
	port, _ := strconv.Atoi(portText)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := sha256.Sum256(leaf.Raw)
	node := map[string]any{"name": c.NodeName, "type": "anytls", "server": c.PublicIP, "port": port, "password": password, "certificate-public-key-sha256": base64.StdEncoding.EncodeToString(spki[:]), "skip-cert-verify": false}
	// JSON is YAML 1.2: nodes-only native YAML without another dependency.
	body, err := json.MarshalIndent(map[string]any{"proxies": []any{node}}, "", "  ")
	if err != nil {
		return nil, nil, zero, err
	}
	body = append(body, '\n')
	path := "/subscribe/" + c.Token
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if (r.Method != "GET" && r.Method != "HEAD") || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.ContentLength > 0 || len(r.TransferEncoding) > 0 || subtle.ConstantTimeCompare([]byte(r.URL.Path), []byte(path)) != 1 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == "GET" {
			_, _ = w.Write(body)
		}
	})
	return h, body, pin, nil
}

// Both listeners are acquired before success. HTTP errors close the AnyTLS
// listener; caller cancellation owns both listeners, without global signals.
func startServerListeners(ctx context.Context, listen string, c *subscriptionConfig, tc *tls.Config, password string) (net.Listener, *http.Server, error) {
	var h http.Handler
	if c != nil {
		p, err := listenPort(listen)
		if err != nil {
			return nil, nil, err
		}
		_, sp, _ := net.SplitHostPort(c.Listen)
		pNum, _ := strconv.Atoi(p)
		spNum, err := strconv.Atoi(sp)
		if err != nil || pNum == spNum {
			return nil, nil, errors.New("AnyTLS and subscription ports must differ")
		}
		var errH error
		h, _, _, errH = subscriptionHandler(*c, tc, listen, password)
		if errH != nil {
			return nil, nil, errH
		}
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, nil, err
	}
	var server *http.Server
	if c != nil {
		sl, err := net.Listen("tcp", c.Listen)
		if err != nil {
			listener.Close()
			return nil, nil, errors.New("cannot bind subscription listener")
		}
		secure := tc.Clone()
		secure.MinVersion = tls.VersionTLS12
		secure.NextProtos = []string{"http/1.1"}
		server = &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: secure}
		go func() {
			_ = server.Serve(tls.NewListener(&subscriptionLimitListener{Listener: sl, slots: make(chan struct{}, 128), done: make(chan struct{})}, secure))
			listener.Close()
		}()
	}
	go func() {
		<-ctx.Done()
		listener.Close()
		if server != nil {
			_ = server.Close()
		}
	}()
	return listener, server, nil
}

type subscriptionLimitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}
type subscriptionLimitConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *subscriptionLimitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
func (l *subscriptionLimitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &subscriptionLimitConn{Conn: c, release: func() { <-l.slots }}, nil
}
func (l *subscriptionLimitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func discoverSubscriptionIP(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 4 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("public IP discovery failed; supply --public-ip")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 129))
	ip := strings.TrimSpace(string(raw))
	if err != nil || resp.StatusCode != 200 || len(raw) > 128 || !subscriptionPublicIP(ip) {
		return "", errors.New("public IP discovery failed; supply --public-ip")
	}
	return ip, nil
}

func runServerConfigSubscription(args []string) error {
	fs := flag.NewFlagSet("config subscription", flag.ContinueOnError)
	configPath := fs.String("config", defaultServerConfigPath(), "server env config")
	subPath := fs.String("subscription-config", "", "private subscription config (default alongside server.env)")
	publicIP := fs.String("public-ip", "", "explicit public numeric IP; otherwise trusted HTTPS discovery on first setup")
	listen := fs.String("subscription-listen", "", "HTTPS listen (first setup :443)")
	name := fs.String("node-name", "", "native node name")
	check := fs.Bool("check-active", false, "verify active local HTTPS identity and body before private link handoff")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected subscription arguments")
	}
	if *subPath == "" {
		*subPath = filepath.Join(filepath.Dir(*configPath), "subscription.json")
	}
	cfg, err := loadServerEnvConfig(*configPath)
	if err != nil {
		return errors.New("cannot load server config")
	}
	c, err := loadSubscriptionConfig(*subPath)
	if err != nil {
		if _, statErr := os.Lstat(*subPath); !errors.Is(statErr, os.ErrNotExist) || *check {
			return errors.New("cannot load private subscription config")
		}
		c = subscriptionConfig{Listen: ":443", NodeName: "AnyTLS"}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		c.Token = base64.RawURLEncoding.EncodeToString(b)
	}
	if *check && (*publicIP != "" || *listen != "" || *name != "") {
		return errors.New("check-active does not modify configuration")
	}
	if *publicIP != "" {
		c.PublicIP = *publicIP
	}
	if *listen != "" {
		c.Listen = *listen
	}
	if *name != "" {
		c.NodeName = *name
	}
	if c.PublicIP == "" {
		c.PublicIP, err = discoverSubscriptionIP(context.Background())
		if err != nil {
			return err
		}
	}
	if err := validateSubscriptionConfig(c); err != nil {
		return err
	}
	p, err := listenPort(cfg.Listen)
	if err != nil {
		return err
	}
	_, sp, _ := net.SplitHostPort(c.Listen)
	pNum, _ := strconv.Atoi(p)
	spNum, _ := strconv.Atoi(sp)
	if pNum == spNum {
		return errors.New("AnyTLS and subscription ports must differ")
	}
	if !*check {
		if err := saveSubscriptionConfig(*subPath, c); err != nil {
			return err
		}
		fmt.Println("Private subscription config prepared; run with --subscription-config, then config subscription --check-active for trusted local handoff.")
		return nil
	}
	// Read existing persistent files only. Never regenerate after server startup.
	certFile, keyFile := cfg.CertFile, cfg.KeyFile
	if cfg.CertDir != "" {
		certFile = filepath.Join(cfg.CertDir, "server.crt")
		keyFile = filepath.Join(cfg.CertDir, "server.key")
	}
	if serverUsesAutoCert(cfg) {
		dir := defaultServerAutoCertDirForConfig(*configPath)
		certFile = filepath.Join(dir, "server.crt")
		keyFile = filepath.Join(dir, "server.key")
	}
	if certFile == "" || keyFile == "" {
		return errors.New("persistent certificate required")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return errors.New("cannot load persistent certificate")
	}
	tc := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	_, expected, pin, err := subscriptionHandler(c, tc, cfg.Listen, cfg.Password)
	if err != nil {
		return err
	}
	if err := checkActiveSubscription(c, pin, expected); err != nil {
		return err
	}
	fmt.Println("PRIVATE credential: share only with the intended client (pin-only trust, not PKIX):")
	fmt.Println(subscriptionURL(c, pin))
	return nil
}
func checkActiveSubscription(c subscriptionConfig, pin [32]byte, expected []byte) error {
	host, port, _ := net.SplitHostPort(c.Listen)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || sha256.Sum256(cs.PeerCertificates[0].Raw) != pin {
			return errors.New("active certificate mismatch")
		}
		return nil
	}}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: tc, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	resp, err := client.Get("https://" + net.JoinHostPort(host, port) + "/subscribe/" + c.Token)
	if err != nil {
		return errors.New("active subscription TLS/GET verification failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(expected)+1)))
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/yaml" || !bytes.Equal(body, expected) {
		return errors.New("active subscription content verification failed")
	}
	return nil
}
