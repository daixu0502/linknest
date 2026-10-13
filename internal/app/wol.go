package app

import (
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"unicode"
)

// parseWOLMAC accepts common copied MAC formats without dropping arbitrary
// characters. Only six-byte Ethernet addresses can become a magic packet.
func parseWOLMAC(value string) (net.HardwareAddr, error) {
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\u200b', '\ufeff': // clipboard zero-width space / BOM
			return -1
		case '\uff1a', '-', '\uff0d', '\u2010', '\u2011', '\u2013', '\u2014', '\u2212':
			return ':'
		case '\uff0e':
			return '.'
		}
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
	if len(value) == 12 {
		if b, err := hex.DecodeString(value); err == nil {
			return net.HardwareAddr(b), nil
		}
	}
	m, err := net.ParseMAC(value)
	if err != nil || len(m) != 6 {
		return nil, errors.New("MAC 地址需为 12 位十六进制数，可使用冒号、短横线或点分隔")
	}
	return m, nil
}
