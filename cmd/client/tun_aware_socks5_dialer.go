package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	t2dialer "github.com/xjasonlyu/tun2socks/v2/dialer"
	t2meta "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2socks5 "github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

const tunDialerTCPConnectTimeout = 5 * time.Second
const tunDialerTCPKeepAlivePeriod = 30 * time.Second

type tunAwareSocks5Dialer struct {
	addr string
	user string
	pass string
	unix bool
}

func newTunAwareSocks5Dialer(addr, user, pass string) (*tunAwareSocks5Dialer, error) {
	if addr == "" {
		return nil, fmt.Errorf("empty socks5 address")
	}
	unix := len(addr) > 0 && addr[0] == '/'
	// Support Linux abstract namespace socket (leading '@' or '\x00').
	if len(addr) > 1 && (addr[0] == '@' || addr[0] == 0x00) {
		addr = addr[1:]
	}
	return &tunAwareSocks5Dialer{
		addr: addr,
		user: user,
		pass: pass,
		unix: unix,
	}, nil
}

func (d *tunAwareSocks5Dialer) DialContext(ctx context.Context, metadata *t2meta.Metadata) (c net.Conn, err error) {
	network := "tcp"
	if d.unix {
		network = "unix"
	}

	c, err = t2dialer.DialContext(ctx, network, d.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", d.addr, err)
	}
	setConnKeepAlive(c)
	if metadata != nil {
		registerTunSourceHint(c.LocalAddr(), metadata.SourceAddress())
	}

	defer func() {
		if err != nil && c != nil {
			_ = c.Close()
		}
	}()

	var user *t2socks5.User
	if d.user != "" {
		user = &t2socks5.User{
			Username: d.user,
			Password: d.pass,
		}
	}

	_, err = t2socks5.ClientHandshake(c, serializeTunSocksAddr(metadata), t2socks5.CmdConnect, user)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (d *tunAwareSocks5Dialer) DialUDP(metadata *t2meta.Metadata) (_ net.PacketConn, err error) {
	if d.unix {
		return nil, fmt.Errorf("%w when unix domain socket is enabled", errors.ErrUnsupported)
	}

	ctx, cancel := context.WithTimeout(context.Background(), tunDialerTCPConnectTimeout)
	defer cancel()

	c, err := t2dialer.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", d.addr, err)
	}
	setConnKeepAlive(c)
	if metadata != nil {
		registerTunSourceHint(c.LocalAddr(), metadata.SourceAddress())
	}

	defer func() {
		if err != nil && c != nil {
			_ = c.Close()
		}
	}()

	var user *t2socks5.User
	if d.user != "" {
		user = &t2socks5.User{
			Username: d.user,
			Password: d.pass,
		}
	}

	// RFC1928: DST is all-zero when client doesn't know outbound UDP endpoint yet.
	var targetAddr t2socks5.Addr = []byte{t2socks5.AtypIPv4, 0, 0, 0, 0, 0, 0}
	addr, err := t2socks5.ClientHandshake(c, targetAddr, t2socks5.CmdUDPAssociate, user)
	if err != nil {
		return nil, fmt.Errorf("client handshake: %w", err)
	}

	pc, err := t2dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen packet: %w", err)
	}

	go func() {
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
		_ = pc.Close()
	}()

	bindAddr := addr.UDPAddr()
	if bindAddr == nil {
		return nil, fmt.Errorf("invalid UDP binding address: %#v", addr)
	}
	if bindAddr.IP.IsUnspecified() {
		udpAddr, resolveErr := net.ResolveUDPAddr("udp", d.addr)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve udp address %s: %w", d.addr, resolveErr)
		}
		bindAddr.IP = udpAddr.IP
	}
	return &tunAwareSocksPacketConn{PacketConn: pc, rAddr: bindAddr, tcpConn: c}, nil
}

type tunAwareSocksPacketConn struct {
	net.PacketConn
	rAddr   net.Addr
	tcpConn net.Conn
}

func (pc *tunAwareSocksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	var packet []byte
	if ma, ok := addr.(*t2meta.Addr); ok {
		packet, err = t2socks5.EncodeUDPPacket(serializeTunSocksAddr(ma.Metadata()), b)
	} else {
		packet, err = t2socks5.EncodeUDPPacket(t2socks5.ParseAddr(addr), b)
	}
	if err != nil {
		return 0, err
	}
	return pc.PacketConn.WriteTo(packet, pc.rAddr)
}

func (pc *tunAwareSocksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := pc.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	addr, payload, err := t2socks5.DecodeUDPPacket(b)
	if err != nil {
		return 0, nil, err
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, fmt.Errorf("convert %s to UDPAddr is nil", addr)
	}

	copy(b, payload)
	return n - len(addr) - 3, udpAddr, nil
}

func (pc *tunAwareSocksPacketConn) Close() error {
	_ = pc.tcpConn.Close()
	return pc.PacketConn.Close()
}

func serializeTunSocksAddr(m *t2meta.Metadata) t2socks5.Addr {
	if m == nil {
		return t2socks5.Addr{t2socks5.AtypIPv4, 0, 0, 0, 0, 0, 0}
	}
	return t2socks5.SerializeAddr("", m.DstIP, m.DstPort)
}

func setConnKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(tunDialerTCPKeepAlivePeriod)
	}
}
