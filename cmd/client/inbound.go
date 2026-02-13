package main

import (
	std_bufio "bufio"
	"context"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"github.com/sirupsen/logrus"
)

type inboundHandler interface {
	NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error
	NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error
}

type proxyErrorLogger struct {
	mu         sync.Mutex
	nextLogAt  time.Time
	suppressed int
	lastMsg    string
}

func (l *proxyErrorLogger) log(err error) {
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
		logrus.Errorf("CreateProxy: %s (suppressed %d repeats)", l.lastMsg, l.suppressed)
	}
	logrus.Errorln("CreateProxy:", err)
	l.lastMsg = msg
	l.nextLogAt = now.Add(2 * time.Second)
	l.suppressed = 0
}

var createProxyErrLogger proxyErrorLogger

type inboundConnTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

var liveInboundConns inboundConnTracker

func trackInboundConn(conn net.Conn) {
	if conn == nil {
		return
	}
	liveInboundConns.mu.Lock()
	if liveInboundConns.conns == nil {
		liveInboundConns.conns = make(map[net.Conn]struct{}, 128)
	}
	liveInboundConns.conns[conn] = struct{}{}
	liveInboundConns.mu.Unlock()
}

func untrackInboundConn(conn net.Conn) {
	if conn == nil {
		return
	}
	liveInboundConns.mu.Lock()
	delete(liveInboundConns.conns, conn)
	liveInboundConns.mu.Unlock()
}

func closeAllInboundConnections(reason string) int {
	liveInboundConns.mu.Lock()
	if len(liveInboundConns.conns) == 0 {
		liveInboundConns.mu.Unlock()
		return 0
	}
	conns := make([]net.Conn, 0, len(liveInboundConns.conns))
	for conn := range liveInboundConns.conns {
		conns = append(conns, conn)
	}
	liveInboundConns.mu.Unlock()

	closed := 0
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		if err := conn.Close(); err == nil {
			closed++
		}
	}
	if closed > 0 {
		logrus.Warnf("[Client] inbound connections closed: count=%d reason=%s", closed, strings.TrimSpace(reason))
	}
	return closed
}

func handleTcpConnection(ctx context.Context, c net.Conn, handler inboundHandler) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()
	defer c.Close()

	reader := std_bufio.NewReader(c)
	headerBytes, err := reader.Peek(1)
	if err != nil {
		return
	}

	metadata := M.Metadata{
		Source:      M.SocksaddrFromNet(c.RemoteAddr()),
		Destination: M.SocksaddrFromNet(c.LocalAddr()),
	}

	switch headerBytes[0] {
	case socks4.Version, socks5.Version:
		_ = socks.HandleConnection0(ctx, c, reader, nil, handler, metadata)
	default:
		_ = http.HandleConnection(ctx, c, reader, nil, handler, metadata)
	}
}

// sing socks inbound

func (c *myClient) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	proxyC, err := c.CreateProxy(ctx, metadata.Destination)
	if err != nil {
		createProxyErrLogger.log(err)
		return err
	}
	defer proxyC.Close()

	return bufio.CopyConn(ctx, conn, proxyC)
}

func (c *myClient) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	proxyC, err := c.CreateProxy(ctx, uot.RequestDestination(2))
	if err != nil {
		createProxyErrLogger.log(err)
		return err
	}
	defer proxyC.Close()

	request := uot.Request{
		Destination: metadata.Destination,
	}
	uotC := uot.NewLazyConn(proxyC, request)

	return bufio.CopyPacketConn(ctx, conn, uotC)
}
