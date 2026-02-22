package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"runtime/debug"
	"strings"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
)

func handleTcpConnection(ctx context.Context, c net.Conn, s *myServer) {
	rawConn := c
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()

	c = tls.Server(c, s.tlsConfig)
	closeConn := true
	defer func() {
		if closeConn {
			_ = c.Close()
		}
	}()

	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(c)
	if err != nil {
		logrus.Debugln("ReadOnceFrom:", err)
		fallback(ctx, rawConn)
		closeConn = false
		return
	}
	c = bufio.NewCachedConn(c, b)

	by, err := b.ReadBytes(32)
	if err != nil || !bytes.Equal(by, passwordSha256) {
		b.Resize(0, n)
		fallback(ctx, rawConn)
		closeConn = false
		return
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		fallback(ctx, rawConn)
		closeConn = false
		return
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			fallback(ctx, rawConn)
			closeConn = false
			return
		}
	}

	session := session.NewServerSession(c, func(stream *session.Stream) {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorln("[BUG]", r, string(debug.Stack()))
			}
		}()
		defer stream.Close()

		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			logrus.Debugln("ReadAddrPort:", err)
			return
		}

		if strings.Contains(destination.String(), "udp-over-tcp.arpa") {
			proxyOutboundUoT(ctx, stream, destination)
		} else {
			proxyOutboundTCP(ctx, stream, destination)
		}
	}, &padding.DefaultPaddingFactory)
	session.Run()
	session.Close()
}

func fallback(ctx context.Context, c net.Conn) {
	if c == nil {
		return
	}
	if tc := unwrapTCPConn(c); tc != nil {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
	logrus.Debugln("fallback-rst:", c.RemoteAddr())
}

func unwrapTCPConn(c net.Conn) *net.TCPConn {
	current := c
	for i := 0; i < 8 && current != nil; i++ {
		if tc, ok := current.(*net.TCPConn); ok {
			return tc
		}
		if unwrap, ok := current.(interface{ NetConn() net.Conn }); ok {
			next := unwrap.NetConn()
			if next == nil || next == current {
				return nil
			}
			current = next
			continue
		}
		if unwrap, ok := current.(interface{ Unwrap() net.Conn }); ok {
			next := unwrap.Unwrap()
			if next == nil || next == current {
				return nil
			}
			current = next
			continue
		}
		return nil
	}
	return nil
}
