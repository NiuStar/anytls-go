package session

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type captureConn struct {
	data []byte
}

func (c *captureConn) Read(_ []byte) (int, error)         { return 0, net.ErrClosed }
func (c *captureConn) Write(p []byte) (int, error)        { c.data = append(c.data, p...); return len(p), nil }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return nil }
func (c *captureConn) RemoteAddr() net.Addr               { return nil }
func (c *captureConn) SetDeadline(_ time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestWriteDataFrameSplitLargePayload(t *testing.T) {
	conn := &captureConn{}
	s := &Session{conn: conn}

	payload := make([]byte, 70*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	n, err := s.writeDataFrame(1, payload)
	if err != nil {
		t.Fatalf("writeDataFrame failed: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("unexpected write size: got %d want %d", n, len(payload))
	}

	offset := 0
	totalPayload := 0
	frameCount := 0
	for offset < len(conn.data) {
		if offset+headerOverHeadSize > len(conn.data) {
			t.Fatalf("truncated frame header at %d", offset)
		}
		cmd := conn.data[offset]
		sid := binary.BigEndian.Uint32(conn.data[offset+1 : offset+5])
		frameLen := int(binary.BigEndian.Uint16(conn.data[offset+5 : offset+7]))
		offset += headerOverHeadSize
		if offset+frameLen > len(conn.data) {
			t.Fatalf("truncated frame payload at %d", offset)
		}
		if cmd != cmdPSH {
			t.Fatalf("unexpected frame cmd: %d", cmd)
		}
		if sid != 1 {
			t.Fatalf("unexpected stream id: %d", sid)
		}
		if frameLen <= 0 || frameLen > int(^uint16(0)) {
			t.Fatalf("invalid frame len: %d", frameLen)
		}
		totalPayload += frameLen
		frameCount++
		offset += frameLen
	}

	if frameCount < 2 {
		t.Fatalf("expected split frames, got %d", frameCount)
	}
	if totalPayload != len(payload) {
		t.Fatalf("payload mismatch: got %d want %d", totalPayload, len(payload))
	}
}
