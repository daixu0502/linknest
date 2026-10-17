//go:build !linux

package app

import (
	"errors"
	"net"
)

func upnpBindInterface(*net.Dialer, string) error {
	return errors.New("指定 UPnP 网卡仅支持 Linux host 网络")
}
