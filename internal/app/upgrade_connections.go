package app

import (
	"bufio"
	"net"
	"net/http"
	"sync"
)

type upgradeConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *upgradeConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type upgradeResponse struct {
	http.ResponseWriter
	connections *sync.Map
	onClose     func(net.Conn)
}

func (w *upgradeResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *upgradeResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, b, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return &upgradeConn{Conn: c, release: func() {
		w.connections.Delete(c)
		if w.onClose != nil {
			w.onClose(c)
		}
	}}, b, nil
}
