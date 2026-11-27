//go:build linux && integration

package tlsspoof

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"testing"
)

func TestAuxiliarySocketUsesOriginalNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("CAP_SYS_ADMIN required")
	}
	type result struct {
		fd  int
		err error
	}
	ready := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		original, err := unix.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			ready <- result{-1, err}
			return
		}
		defer unix.Close(original)
		if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- result{-1, err}
			return
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		restore := unix.Setns(original, unix.CLONE_NEWNET)
		if err == nil {
			err = restore
		}
		ready <- result{fd, err}
	}()
	source := <-ready
	if source.err != nil {
		t.Fatal(source.err)
	}
	defer unix.Close(source.fd)
	expected, err := unix.GetsockoptUint64(source.fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	var actual uint64
	if err = inSocketNamespace(source.fd, func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		actual, err = unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("auxiliary namespace cookie %d != original %d", actual, expected)
	}
}
