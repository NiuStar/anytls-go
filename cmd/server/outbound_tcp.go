package main

import (
	"anytls/proxy"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sirupsen/logrus"
)

type clientSettingReader interface {
	ClientSetting(key string) string
}

func clientSettingFromConn(conn net.Conn, key string) string {
	settings, ok := conn.(clientSettingReader)
	if !ok {
		return ""
	}
	return strings.TrimSpace(settings.ClientSetting(key))
}

func resolveEgressIP(conn net.Conn, destination M.Socksaddr) string {
	ruleRaw := clientSettingFromConn(conn, "egress-rule")
	if ruleRaw != "" {
		if ip, ok := matchEgressRule(ruleRaw, destination); ok {
			return ip
		}
	}
	return clientSettingFromConn(conn, "egress-ip")
}

func matchEgressRule(ruleRaw string, destination M.Socksaddr) (string, bool) {
	for _, entry := range splitRuleEntries(ruleRaw) {
		pattern, egressIP, ok := parseRuleEntry(entry)
		if !ok {
			continue
		}
		if rulePatternMatch(pattern, destination) {
			return egressIP, true
		}
	}
	return "", false
}

func splitRuleEntries(ruleRaw string) []string {
	return strings.FieldsFunc(ruleRaw, func(r rune) bool {
		return r == ';' || r == ',' || r == '\n'
	})
}

func parseRuleEntry(entry string) (pattern, egressIP string, ok bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", "", false
	}

	kv := strings.SplitN(entry, "=", 2)
	if len(kv) != 2 {
		return "", "", false
	}
	pattern = strings.TrimSpace(kv[0])
	egressIP = strings.TrimSpace(kv[1])
	if pattern == "" || egressIP == "" {
		return "", "", false
	}

	ip := net.ParseIP(egressIP)
	if ip == nil {
		return "", "", false
	}
	return pattern, ip.String(), true
}

func rulePatternMatch(pattern string, destination M.Socksaddr) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" {
		return false
	}
	if p == "*" || p == "default" {
		return true
	}

	destIsDomain := destination.IsFqdn()
	destDomain := strings.ToLower(strings.TrimSpace(destination.Fqdn))
	destIsIP := destination.IsIP()
	destIP := destination.Addr.Unmap()

	switch {
	case strings.HasPrefix(p, "domain:"):
		match := strings.TrimSpace(strings.TrimPrefix(p, "domain:"))
		return destIsDomain && destDomain == match
	case strings.HasPrefix(p, "suffix:"):
		match := strings.TrimSpace(strings.TrimPrefix(p, "suffix:"))
		if !destIsDomain || match == "" {
			return false
		}
		return destDomain == match || strings.HasSuffix(destDomain, "."+match)
	case strings.HasPrefix(p, "ip:"):
		match := strings.TrimSpace(strings.TrimPrefix(p, "ip:"))
		return matchIPPattern(match, destIsIP, destIP)
	case strings.HasPrefix(p, "cidr:"):
		match := strings.TrimSpace(strings.TrimPrefix(p, "cidr:"))
		return matchCIDRPattern(match, destIsIP, destIP)
	}

	if strings.HasPrefix(p, "*.") {
		match := strings.TrimPrefix(p, "*.")
		if !destIsDomain || match == "" {
			return false
		}
		return destDomain == match || strings.HasSuffix(destDomain, "."+match)
	}
	if strings.Contains(p, "/") {
		return matchCIDRPattern(p, destIsIP, destIP)
	}
	if matchIPPattern(p, destIsIP, destIP) {
		return true
	}
	return destIsDomain && destDomain == p
}

func matchIPPattern(pattern string, destIsIP bool, destIP netip.Addr) bool {
	if !destIsIP {
		return false
	}
	ip, err := netip.ParseAddr(pattern)
	if err != nil {
		return false
	}
	return destIP == ip.Unmap()
}

func matchCIDRPattern(pattern string, destIsIP bool, destIP netip.Addr) bool {
	if !destIsIP {
		return false
	}
	prefix, err := netip.ParsePrefix(pattern)
	if err != nil {
		return false
	}
	return prefix.Contains(destIP)
}

func dialTCPWithEgressIP(ctx context.Context, destination, egressIP string) (net.Conn, error) {
	if egressIP == "" {
		return proxy.SystemDialer.DialContext(ctx, "tcp", destination)
	}
	ip := net.ParseIP(egressIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid egress-ip: %s", egressIP)
	}

	dialer := *proxy.SystemDialer
	dialer.LocalAddr = &net.TCPAddr{
		IP: ip,
	}
	return dialer.DialContext(ctx, "tcp", destination)
}

func proxyOutboundTCP(ctx context.Context, conn net.Conn, destination M.Socksaddr) error {
	c, err := dialTCPWithEgressIP(ctx, destination.String(), resolveEgressIP(conn, destination))
	if err != nil {
		logrus.Debugln("proxyOutboundTCP DialContext:", err)
		err = E.Errors(err, N.ReportHandshakeFailure(conn, err))
		return err
	}

	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		return err
	}

	return bufio.CopyConn(ctx, conn, c)
}

func proxyOutboundUoT(ctx context.Context, conn net.Conn, destination M.Socksaddr) error {
	request, err := uot.ReadRequest(conn)
	if err != nil {
		logrus.Debugln("proxyOutboundUoT ReadRequest:", err)
		return err
	}

	c, err := listenPacketWithEgressIP(ctx, resolveEgressIP(conn, request.Destination))
	if err != nil {
		logrus.Debugln("proxyOutboundUoT ListenPacket:", err)
		err = E.Errors(err, N.ReportHandshakeFailure(conn, err))
		return err
	}

	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		return err
	}

	return bufio.CopyPacketConn(ctx, uot.NewConn(conn, *request), bufio.NewPacketConn(c))
}

func listenPacketWithEgressIP(ctx context.Context, egressIP string) (net.PacketConn, error) {
	if egressIP == "" {
		return net.ListenPacket("udp", "")
	}
	ip := net.ParseIP(egressIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid egress-ip: %s", egressIP)
	}

	lc := net.ListenConfig{}
	return lc.ListenPacket(ctx, "udp", net.JoinHostPort(ip.String(), "0"))
}
