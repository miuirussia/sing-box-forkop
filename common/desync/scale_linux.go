package desync

import (
	"encoding/binary"
	"fmt"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

func verifyScale(conn any, want int, explicit bool) error {
	if want == 0 && !explicit {
		return nil
	}
	sc, ok := common.Cast[syscall.Conn](conn)
	if !ok {
		return fmt.Errorf("desync: wscale requires owned TCP socket")
	}
	return control.Conn(sc, func(fd uintptr) error {
		var info [256]byte
		size := uint32(len(info))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_INFO, uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			return errno
		}
		// tcp_info's native C bitfields put rcv_wscale in the high nibble
		// on little endian and the low nibble on big endian architectures.
		got := int(info[6] >> 4)
		if binary.NativeEndian.Uint16([]byte{1, 2}) == 0x0102 {
			got = int(info[6] & 15)
		}

		if got != want {
			return fmt.Errorf("desync: requested wscale=%d, negotiated %d; peer/kernel window scaling unavailable or pre-SYN hook was not installed", want, got)
		}
		return nil
	})
}
