//go:build linux && integration

package desync

import (
	"bytes"
	"context"
	"io"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
)

func BenchmarkRelayCopy(b *testing.B) {
	for _, mode := range []string{"none", "split"} {
		b.Run(mode, func(b *testing.B) {
			body := bytes.Repeat([]byte("relay payload\x00\xff"), 2*1024*1024)
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			var before, after syscall.Rusage
			_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
			for b.Loop() {
				sender, source := copyTCPPair(b)
				target, receiver := copyTCPPair(b)
				conn, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: mode, SplitPos: "1"})
				if err != nil {
					b.Fatal(err)
				}
				received := make(chan int64, 1)
				go func() { n, _ := io.Copy(io.Discard, receiver); received <- n }()
				go func() { _, _ = sender.Write(body); _ = sender.CloseWrite() }()
				n, err := bufio.Copy(conn, source)
				_ = conn.Close()
				if got := <-received; err != nil || n != int64(len(body)) || got != n {
					b.Fatalf("copy %d/%d: %v", n, got, err)
				}
				_ = sender.Close()
				_ = source.Close()
				_ = receiver.Close()
			}
			_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
			cpuNS := after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano()
			b.ReportMetric(float64(cpuNS)/float64(b.N), "cpu-ns/op")
		})
	}
}
