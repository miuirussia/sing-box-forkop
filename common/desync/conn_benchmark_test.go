package desync

import (
	"context"
	"net"
	"testing"
	"time"
)

type discardConn struct{}

func (discardConn) Write(b []byte) (int, error)      { return len(b), nil }
func (discardConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (discardConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

// Compare the established stream after the first flight; crypto, socket I/O and
// allocations in the transport itself are deliberately outside this benchmark.
func BenchmarkStreamWrite(b *testing.B) {
	payload := make([]byte, 32*1024)
	b.Run("direct", func(b *testing.B) {
		var c net.Conn = discardConn{}
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for b.Loop() {
			_, _ = c.Write(payload)
		}
	})
	b.Run("desync_after_first_flight", func(b *testing.B) {
		c := &Conn{Conn: discardConn{}, ctx: context.Background(), finished: true, closed: make(chan struct{}), changed: make(chan struct{})}
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for b.Loop() {
			_, _ = c.Write(payload)
		}
	})
}
