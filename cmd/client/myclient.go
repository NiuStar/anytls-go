package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"anytls/util"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type myClient struct {
	passwordSha256 []byte
	dialOut        util.DialOutFunc
	sessionClient  *session.Client
	label          string
	createProxyFn  func(context.Context, M.Socksaddr) (net.Conn, error)
	closeFn        func() error
}

func NewMyClient(ctx context.Context, dialOut util.DialOutFunc, minIdleSession int, egressIP, egressRule, password, label string) *myClient {
	sum := sha256.Sum256([]byte(password))
	label = strings.TrimSpace(label)
	s := &myClient{
		passwordSha256: sum[:],
		dialOut:        dialOut,
		label:          label,
	}
	settings := util.StringMap{}
	if egressIP != "" {
		settings["egress-ip"] = egressIP
	}
	if egressRule != "" {
		settings["egress-rule"] = egressRule
	}
	s.sessionClient = session.NewClient(ctx, s.createOutboundConnection, &padding.DefaultPaddingFactory, time.Second*30, time.Second*30, minIdleSession, settings)
	return s
}

func (c *myClient) Close() error {
	var firstErr error
	if c.sessionClient != nil {
		if err := c.sessionClient.Close(); err != nil {
			firstErr = err
		}
	}
	if c.closeFn != nil {
		if err := c.closeFn(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *myClient) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if c.createProxyFn != nil {
		return c.createProxyFn(ctx, destination)
	}
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		if c.label != "" {
			return nil, fmt.Errorf("%s: %w", c.label, err)
		}
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *myClient) createOutboundConnection(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	b := buf.NewPacket()
	defer b.Release()

	b.Write(c.passwordSha256)
	var paddingLen int
	if pad := padding.DefaultPaddingFactory.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	_, err = b.WriteTo(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func NewSOCKSBridgeClient(label string, spec socksBridgeSpec, closeFn func() error) *myClient {
	return &myClient{
		label: label,
		createProxyFn: func(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
			return dialSOCKS5Connect(ctx, spec, destination)
		},
		closeFn: closeFn,
	}
}
