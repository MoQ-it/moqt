// Package rawquic runs MOQT directly over a quic-go connection negotiated
// with ALPN moqt-22.
package rawquic

import (
	"context"

	"github.com/MoQ-it/moqt"
	"github.com/quic-go/quic-go"
)

// Conn adapts a *quic.Conn to moqt.Conn.
type Conn struct {
	c *quic.Conn
}

func New(c *quic.Conn) *Conn { return &Conn{c: c} }

// QUIC returns the underlying connection, e.g. for ConnectionStats.
func (c *Conn) QUIC() *quic.Conn { return c.c }

func (c *Conn) AcceptStream(ctx context.Context) (moqt.Stream, error) {
	s, err := c.c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return stream{s}, nil
}

func (c *Conn) AcceptUniStream(ctx context.Context) (moqt.ReceiveStream, error) {
	s, err := c.c.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return receiveStream{s}, nil
}

func (c *Conn) OpenStreamSync(ctx context.Context) (moqt.Stream, error) {
	s, err := c.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return stream{s}, nil
}

func (c *Conn) OpenUniStreamSync(ctx context.Context) (moqt.SendStream, error) {
	s, err := c.c.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return sendStream{s}, nil
}

func (c *Conn) SendDatagram(b []byte) error                         { return c.c.SendDatagram(b) }
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) { return c.c.ReceiveDatagram(ctx) }
func (c *Conn) Context() context.Context                            { return c.c.Context() }
func (c *Conn) WebTransport() bool                                  { return false }

func (c *Conn) CloseWithError(code uint64, reason string) error {
	return c.c.CloseWithError(quic.ApplicationErrorCode(code), reason)
}

// urgency maps a MOQT priority (0-255, lower first) onto the RFC 9218
// urgencies quic-go schedules by (0-7).
func urgency(p uint8) int8 { return int8(p >> 5) }

type sendStream struct{ s *quic.SendStream }

func (s sendStream) Write(b []byte) (int, error) { return s.s.Write(b) }
func (s sendStream) Close() error                { return s.s.Close() }
func (s sendStream) Context() context.Context    { return s.s.Context() }
func (s sendStream) CancelWrite(code uint64)     { s.s.CancelWrite(quic.StreamErrorCode(code)) }
func (s sendStream) SetPriority(p uint8)         { s.s.SetPriority(urgency(p), false) }

type receiveStream struct{ s *quic.ReceiveStream }

func (s receiveStream) Read(b []byte) (int, error) { return s.s.Read(b) }
func (s receiveStream) CancelRead(code uint64)     { s.s.CancelRead(quic.StreamErrorCode(code)) }

type stream struct{ s *quic.Stream }

func (s stream) Write(b []byte) (int, error) { return s.s.Write(b) }
func (s stream) Read(b []byte) (int, error)  { return s.s.Read(b) }
func (s stream) Close() error                { return s.s.Close() }
func (s stream) Context() context.Context    { return s.s.Context() }
func (s stream) CancelWrite(code uint64)     { s.s.CancelWrite(quic.StreamErrorCode(code)) }
func (s stream) CancelRead(code uint64)      { s.s.CancelRead(quic.StreamErrorCode(code)) }
func (s stream) SetPriority(p uint8)         { s.s.SetPriority(urgency(p), false) }
