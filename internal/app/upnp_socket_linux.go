package app

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func upnpBindInterface(d *net.Dialer, name string) error {
	if _, err := net.InterfaceByName(name); err != nil {
		return fmt.Errorf("UPnP 网卡不可用：%w", err)
	}
	d.Control = func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
		}); err != nil {
			return err
		}
		if sockErr != nil {
			return fmt.Errorf("无法绑定 UPnP 网卡（host 网络需 NET_RAW）：%w", sockErr)
		}
		return nil
	}
	return nil
}
