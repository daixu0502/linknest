package access

import (
	"bufio"
	"net"
	"net/http"
)

// Preserve streaming and WebSocket capabilities while observing the final status.
type Response struct {
	http.ResponseWriter
	Status int
}

func (w *Response) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *Response) WriteHeader(code int) {
	if code < 200 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if w.Status != 0 {
		return
	}
	w.Status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *Response) Write(b []byte) (int, error) {
	if w.Status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (w *Response) FlushError() error {
	if w.Status == 0 {
		w.WriteHeader(200)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *Response) Flush() { _ = w.FlushError() }
func (w *Response) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, b, e := http.NewResponseController(w.ResponseWriter).Hijack()
	if e == nil {
		w.Status = 101
	}
	return c, b, e
}
