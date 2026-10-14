// Package wt runs MOQT over a webtransport-go session.
package wt

import (
	"context"

	"github.com/MoQ-it/moqt"
	"github.com/quic-go/webtransport-go"
)

// Conn adapts a *webtransport.Session to moqt.Conn.
type Conn struct {
	s *webtransport.Session
}

func New(s *webtransport.Session) *Conn { return &Conn{s: s} }

func (c *Conn) Session() *webtransport.Session { return c.s }

func (c *Conn) AcceptStream(ctx context.Context) (moqt.Stream, error) {
	s, err := c.s.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return stream{s}, nil
}

func (c *Conn) AcceptUniStream(ctx context.Context) (moqt.ReceiveStream, error) {
	s, err := c.s.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return receiveStream{s}, nil
}

func (c *Conn) OpenStreamSync(ctx context.Context) (moqt.Stream, error) {
	s, err := c.s.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return stream{s}, nil
}

func (c *Conn) OpenUniStreamSync(ctx context.Context) (moqt.SendStream, error) {
	s, err := c.s.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return sendStream{s}, nil
}

func (c *Conn) SendDatagram(b []byte) error                         { return c.s.SendDatagram(b) }
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) { return c.s.ReceiveDatagram(ctx) }
func (c *Conn) Context() context.Context                            { return c.s.Context() }
func (c *Conn) WebTransport() bool                                  { return true }

// WebTransport error codes are 32-bit; MOQT codes in use fit.
func (c *Conn) CloseWithError(code uint64, reason string) error {
	return c.s.CloseWithError(webtransport.SessionErrorCode(code), reason)
}

// webtransport-go v0.13 does not expose stream priorities, so SetPriority
// is a no-op; the underlying quic-go streams support it.
// TODO: upstream a SetPriority pass-through.

type sendStream struct{ s *webtransport.SendStream }

func (s sendStream) Write(b []byte) (int, error) { return s.s.Write(b) }
func (s sendStream) Close() error                { return s.s.Close() }
func (s sendStream) Context() context.Context    { return s.s.Context() }
func (s sendStream) CancelWrite(code uint64)     { s.s.CancelWrite(webtransport.StreamErrorCode(code)) }
func (s sendStream) SetPriority(uint8)           {}

type receiveStream struct{ s *webtransport.ReceiveStream }

func (s receiveStream) Read(b []byte) (int, error) { return s.s.Read(b) }
func (s receiveStream) CancelRead(code uint64)     { s.s.CancelRead(webtransport.StreamErrorCode(code)) }

type stream struct{ s *webtransport.Stream }

func (s stream) Write(b []byte) (int, error) { return s.s.Write(b) }
func (s stream) Read(b []byte) (int, error)  { return s.s.Read(b) }
func (s stream) Close() error                { return s.s.Close() }
func (s stream) Context() context.Context    { return s.s.Context() }
func (s stream) CancelWrite(code uint64)     { s.s.CancelWrite(webtransport.StreamErrorCode(code)) }
func (s stream) CancelRead(code uint64)      { s.s.CancelRead(webtransport.StreamErrorCode(code)) }
func (s stream) SetPriority(uint8)           {}
