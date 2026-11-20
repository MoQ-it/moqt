package ws

import (
	"errors"

	"github.com/quic-go/quic-go/quicvarint"
)

// Each binary WebSocket message carries one frame: a varint type, then
//
//	STREAM (0x08, 0x09 with FIN)  stream ID, data to the end
//	RESET_STREAM (0x04)            stream ID, error code
//	STOP_SENDING (0x05)            stream ID, error code
//	DATAGRAM (0x30)                payload to the end
//	CONNECTION_CLOSE (0x1d)        error code, reason to the end
//
// Stream IDs are QUIC's. Data on a stream arrives in order, so frames
// carry no offsets, and TCP's flow control replaces QUIC's.
const (
	frameStream      = 0x08
	frameStreamFin   = 0x09
	frameResetStream = 0x04
	frameStopSending = 0x05
	frameDatagram    = 0x30
	frameClose       = 0x1d
)

type frame struct {
	typ  uint64 // frameStream for both STREAM types
	id   uint64
	fin  bool
	code uint64
	data []byte
}

var errMalformed = errors.New("malformed frame")

func appendStream(b []byte, id uint64, fin bool, data []byte) []byte {
	t := uint64(frameStream)
	if fin {
		t = frameStreamFin
	}
	b = quicvarint.Append(b, t)
	b = quicvarint.Append(b, id)
	return append(b, data...)
}

func appendCode(b []byte, typ, id, code uint64) []byte {
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, id)
	return quicvarint.Append(b, code)
}

func appendDatagram(b, data []byte) []byte {
	b = quicvarint.Append(b, frameDatagram)
	return append(b, data...)
}

func appendClose(b []byte, code uint64, reason string) []byte {
	b = quicvarint.Append(b, frameClose)
	b = quicvarint.Append(b, code)
	return append(b, reason...)
}

func parseFrame(b []byte) (frame, error) {
	var f frame
	t, n, err := quicvarint.Parse(b)
	if err != nil {
		return f, errMalformed
	}
	b = b[n:]
	varint := func() (uint64, bool) {
		v, n, err := quicvarint.Parse(b)
		if err != nil {
			return 0, false
		}
		b = b[n:]
		return v, true
	}
	var ok bool
	switch t {
	case frameStream, frameStreamFin:
		f.typ, f.fin = frameStream, t == frameStreamFin
		if f.id, ok = varint(); !ok {
			return f, errMalformed
		}
		f.data = b
	case frameResetStream, frameStopSending:
		f.typ = t
		if f.id, ok = varint(); !ok {
			return f, errMalformed
		}
		if f.code, ok = varint(); !ok || len(b) != 0 {
			return f, errMalformed
		}
	case frameDatagram:
		f.typ, f.data = t, b
	case frameClose:
		f.typ = t
		if f.code, ok = varint(); !ok {
			return f, errMalformed
		}
		f.data = b
	default:
		return f, errors.New("unknown frame type")
	}
	return f, nil
}
