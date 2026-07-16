package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"net"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
)

const serverInboundHandshakeTimeout = 10 * time.Second

func handleTcpConnection(ctx context.Context, c net.Conn, s *myServer) {
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
	if err := c.SetDeadline(time.Now().Add(serverInboundHandshakeTimeout)); err != nil {
		return
	}
	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		logrus.Debugln("tls handshake:", err)
		return
	}

	b := buf.NewPacket()
	defer b.Release()

	_, err := b.ReadOnceFrom(c)
	if err != nil {
		logrus.Debugln("ReadOnceFrom:", err)
		return
	}
	payload := append([]byte(nil), b.Bytes()...)
	c = bufio.NewCachedConn(c, b)

	by, err := b.ReadBytes(32)
	if err != nil || subtle.ConstantTimeCompare(by, passwordSha256) != 1 {
		fallbackTLS(c, payload)
		return
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		fallbackTLS(c, payload)
		return
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			fallbackTLS(c, payload)
			return
		}
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return
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

func closeInboundConnection(c net.Conn) {
	if c != nil {
		_ = c.Close()
	}
}

func fallbackTLS(c net.Conn, payload []byte) {
	if c == nil {
		return
	}
	if looksLikeHTTPRequest(payload) {
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\nNot Found\n"))
	}
	logrus.Debugln("fallback-close:", c.RemoteAddr())
}

func looksLikeHTTPRequest(payload []byte) bool {
	lineEnd := strings.Index(string(payload), "\r\n")
	if lineEnd <= 0 || lineEnd > 8192 {
		return false
	}
	parts := strings.Split(string(payload[:lineEnd]), " ")
	if len(parts) != 3 || (parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0") {
		return false
	}
	switch parts[0] {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return strings.HasPrefix(parts[1], "/") || parts[0] == "CONNECT"
	default:
		return false
	}
}
