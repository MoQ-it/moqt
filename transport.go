// Package moqt implements MOQT sessions (draft-ietf-moq-transport-22) over
// raw QUIC or WebTransport. Wire encoding lives in wire/v22.
package moqt

import (
	"context"
	"io"
)

// Conn is the transport under a session: a QUIC connection or a
// WebTransport session. Adapters live in transport/rawquic and
// transport/wt.
type Conn interface {
	AcceptStream(ctx context.Context) (Stream, error)
	AcceptUniStream(ctx context.Context) (ReceiveStream, error)
	OpenStreamSync(ctx context.Context) (Stream, error)
	OpenUniStreamSync(ctx context.Context) (SendStream, error)
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	CloseWithError(code uint64, reason string) error
	// Context is cancelled when the transport closes.
	Context() context.Context
	// WebTransport reports whether this is a WebTransport session, where
	// the PATH and AUTHORITY setup options must not be used.
	WebTransport() bool
}

// SendStream is the sending half of a stream.
type SendStream interface {
	io.Writer
	// Close ends the stream with a FIN.
	Close() error
	// CancelWrite resets the stream with an application error code.
	CancelWrite(code uint64)
	// SetPriority sets the scheduling urgency, 0 (most urgent) to 255, as
	// MOQT priorities are expressed. Transports that cannot prioritise
	// streams ignore it.
	SetPriority(priority uint8)
	// Context is cancelled when the send side is closed or reset, or the
	// peer sends STOP_SENDING.
	Context() context.Context
}

// ReceiveStream is the receiving half of a stream.
type ReceiveStream interface {
	io.Reader
	// CancelRead sends STOP_SENDING with an application error code.
	CancelRead(code uint64)
}

// Stream is a bidirectional stream.
type Stream interface {
	SendStream
	ReceiveStream
}
