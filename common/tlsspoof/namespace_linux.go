package tlsspoof

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// inSocketNamespace creates auxiliary sockets in the original socket's network
// namespace, even after the direct dialer's temporary setns has been restored.
// The common case compares cookies and stays on this goroutine. A namespace
// switch runs on an isolated locked thread, which is discarded if restore fails.
func inSocketNamespace(socket int, operation func() error) error {
	probe, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	own, e1 := unix.GetsockoptUint64(probe, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	target, e2 := unix.GetsockoptUint64(socket, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	unix.Close(probe)
	if e1 == nil && e2 == nil && own == target {
		return operation()
	}
	namespace, err := unix.IoctlRetInt(socket, unix.SIOCGSKNS)
	if err != nil {
		return fmt.Errorf("desync: access original socket network namespace (CAP_NET_ADMIN required): %w", err)
	}
	defer unix.Close(namespace)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		unlock := true
		defer func() {
			if unlock {
				runtime.UnlockOSThread()
			}
		}()
		original, err := unix.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			done <- err
			return
		}
		defer unix.Close(original)
		var from, to unix.Stat_t
		if unix.Fstat(original, &from) == nil && unix.Fstat(namespace, &to) == nil && from.Dev == to.Dev && from.Ino == to.Ino {
			done <- operation()
			return
		}
		if err = unix.Setns(namespace, unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("desync: enter socket network namespace (CAP_SYS_ADMIN required): %w", err)
			return
		}
		err = operation()
		restore := unix.Setns(original, unix.CLONE_NEWNET)
		if restore != nil {
			unlock = false
			err = errors.Join(err, fmt.Errorf("desync: restore network namespace: %w", restore))
		}
		done <- err
	}()
	return <-done
}
