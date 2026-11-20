// Package ws runs MOQT over a WebSocket, for browsers without
// WebTransport. Streams and datagrams are multiplexed over the one
// connection with QUIC-style frames (see frame.go), so they share TCP's
// ordering: a lost packet delays every stream.
package ws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/MoQ-it/moqt"
	"github.com/coder/websocket"
)

// Subprotocol is the WebSocket subprotocol both ends must offer.
const Subprotocol = "moqt-22+ws"

const (
	// maxChunk bounds a STREAM frame, so an urgent stream waits for at
	// most one chunk of another.
	maxChunk = 16 << 10
	// sendBuffer is how much a stream queues before Write blocks. Queued
	// data can still be dropped by a reset; data written to the socket
	// cannot.
	sendBuffer = 64 << 10
	// maxUnread caps data received but not yet read, over all streams.
	maxUnread = 64 << 20
	// maxDatagramQueue bounds queued datagrams; beyond it they are
	// dropped, as an unreliable datagram would be.
	maxDatagramQueue = 64 << 10
	maxDatagram      = 64 << 10
	maxMessage       = max(maxChunk, maxDatagram) + 64
	maxBidiStreams   = 1 << 12
	maxUniStreams    = 1 << 14
	// A peer that stops answering pings is gone, like a QUIC idle timeout.
	pingInterval = 5 * time.Second
	pingTimeout  = 15 * time.Second
)

// CloseError is why a connection closed: the peer's or our own
// CONNECTION_CLOSE.
type CloseError struct {
	Code   uint64
	Reason string
	Remote bool
}

func (e *CloseError) Error() string {
	side := "local"
	if e.Remote {
		side = "remote"
	}
	return fmt.Sprintf("ws: connection closed by %s (%d): %s", side, e.Code, e.Reason)
}

// StreamError is returned by Read after the peer reset the stream, and by
// Write after it asked us to stop or we reset it.
type StreamError struct {
	Code   uint64
	Remote bool
}

func (e *StreamError) Error() string {
	if e.Remote {
		return fmt.Sprintf("ws: stream reset by peer (%d)", e.Code)
	}
	return fmt.Sprintf("ws: stream cancelled (%d)", e.Code)
}

var errClosedStream = errors.New("ws: write on closed stream")

// Accept upgrades an HTTP request to a MOQT WebSocket connection. Origins
// are not checked: access is controlled by the MOQT authorization token.
func Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}, InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	if c.Subprotocol() != Subprotocol {
		c.Close(websocket.StatusPolicyViolation, "subprotocol "+Subprotocol+" required")
		return nil, errors.New("ws: client did not offer " + Subprotocol)
	}
	return newConn(c, false), nil
}

// Dial opens a MOQT WebSocket connection to a wss:// (or ws://) URL.
func Dial(ctx context.Context, url string, opts *websocket.DialOptions) (*Conn, error) {
	o := websocket.DialOptions{}
	if opts != nil {
		o = *opts
	}
	o.Subprotocols = []string{Subprotocol}
	c, _, err := websocket.Dial(ctx, url, &o)
	if err != nil {
		return nil, err
	}
	if c.Subprotocol() != Subprotocol {
		c.Close(websocket.StatusPolicyViolation, "subprotocol "+Subprotocol+" required")
		return nil, errors.New("ws: server did not accept " + Subprotocol)
	}
	return newConn(c, true), nil
}

// Conn is a MOQT transport over one WebSocket; it implements moqt.Conn.
type Conn struct {
	ws     *websocket.Conn
	client bool
	ctx    context.Context
	cancel context.CancelCauseFunc
	work   chan struct{}

	acceptBidi chan *stream
	acceptUni  chan *stream
	dgrams     chan []byte

	mu         sync.Mutex
	streams    map[uint64]*stream
	ready      map[*stream]struct{} // streams with data or a FIN to send
	ctrl       [][]byte
	outDgrams  [][]byte
	dgramBytes int
	nextLocal  [2]uint64 // stream counts by kind: 0 bidirectional, 1 unidirectional
	nextPeer   [2]uint64
	unread     int
	closing    []byte // CONNECTION_CLOSE to send last
}

func newConn(ws *websocket.Conn, client bool) *Conn {
	ws.SetReadLimit(maxMessage)
	c := &Conn{
		ws: ws, client: client, work: make(chan struct{}, 1),
		acceptBidi: make(chan *stream, maxBidiStreams), acceptUni: make(chan *stream, maxUniStreams),
		dgrams:  make(chan []byte, 256),
		streams: map[uint64]*stream{}, ready: map[*stream]struct{}{},
	}
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	go c.readLoop()
	go c.writeLoop()
	go c.pingLoop()
	return c
}

func (c *Conn) signal() {
	select {
	case c.work <- struct{}{}:
	default:
	}
}

// streamID numbers streams as QUIC does: bit 0 is the initiator (1 for the
// server), bit 1 set for unidirectional.
func streamID(count uint64, uni, server bool) uint64 {
	id := count << 2
	if server {
		id |= 1
	}
	if uni {
		id |= 2
	}
	return id
}

func (c *Conn) open(uni bool) (*stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return nil, context.Cause(c.ctx)
	}
	kind := 0
	if uni {
		kind = 1
	}
	s := c.newStream(streamID(c.nextLocal[kind], uni, !c.client), true, !uni)
	c.nextLocal[kind]++
	c.streams[s.id] = s
	return s, nil
}

func (c *Conn) AcceptStream(ctx context.Context) (moqt.Stream, error) {
	select {
	case s := <-c.acceptBidi:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

func (c *Conn) AcceptUniStream(ctx context.Context) (moqt.ReceiveStream, error) {
	select {
	case s := <-c.acceptUni:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

// Streams are not limited by the peer, so opening never waits.
func (c *Conn) OpenStreamSync(context.Context) (moqt.Stream, error) { return c.open(false) }

func (c *Conn) OpenUniStreamSync(context.Context) (moqt.SendStream, error) { return c.open(true) }

// SendDatagram queues a datagram. Like a datagram lost in the network, it
// is dropped when too many are waiting for the socket.
func (c *Conn) SendDatagram(b []byte) error {
	if len(b) > maxDatagram {
		return errors.New("ws: datagram too large")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return context.Cause(c.ctx)
	}
	if c.dgramBytes+len(b) > maxDatagramQueue {
		return nil
	}
	c.outDgrams = append(c.outDgrams, appendDatagram(nil, b))
	c.dgramBytes += len(b)
	c.signal()
	return nil
}

func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.dgrams:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

func (c *Conn) Context() context.Context { return c.ctx }

// WebTransport is true: like a WebTransport session, the connection's URL
// already names the endpoint, so PATH and AUTHORITY must not be sent.
func (c *Conn) WebTransport() bool { return true }

// CloseWithError sends CONNECTION_CLOSE, dropping unsent stream data as
// QUIC does, and closes the WebSocket.
func (c *Conn) CloseWithError(code uint64, reason string) error {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return nil
	}
	c.closing = appendClose(nil, code, reason)
	c.mu.Unlock()
	c.signal()
	c.shutdown(&CloseError{Code: code, Reason: reason})
	return nil
}

// shutdown ends the connection and every stream with err.
func (c *Conn) shutdown(err error) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	c.cancel(err)
	for _, s := range c.streams {
		s.fail(err)
	}
	c.mu.Unlock()
}

func (c *Conn) pingLoop() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(c.ctx, pingTimeout)
		err := c.ws.Ping(ctx)
		cancel()
		if err != nil && c.ctx.Err() == nil {
			c.shutdown(&CloseError{Code: 0, Reason: "ping timeout"})
			c.ws.CloseNow()
			return
		}
	}
}

func (c *Conn) writeLoop() {
	defer c.ws.CloseNow()
	for {
		frame, last := c.nextFrame()
		if frame == nil {
			select {
			case <-c.work:
				continue
			case <-c.ctx.Done():
				// shutdown may race the CONNECTION_CLOSE being queued.
				if f, _ := c.nextFrame(); f == nil {
					return
				}
				continue
			}
		}
		if err := c.ws.Write(context.Background(), websocket.MessageBinary, frame); err != nil {
			c.shutdown(fmt.Errorf("ws: %w", err))
			return
		}
		if last {
			c.ws.Close(websocket.StatusNormalClosure, "")
			return
		}
	}
}

// nextFrame takes the next frame to send: control frames, then datagrams,
// then a chunk of the most urgent stream; after shutdown only the
// CONNECTION_CLOSE. last is set for the CONNECTION_CLOSE.
func (c *Conn) nextFrame() (frame []byte, last bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		f := c.closing
		c.closing = nil
		return f, f != nil
	}
	if len(c.ctrl) > 0 {
		f := c.ctrl[0]
		c.ctrl = c.ctrl[1:]
		return f, false
	}
	if len(c.outDgrams) > 0 {
		f := c.outDgrams[0]
		c.outDgrams = c.outDgrams[1:]
		c.dgramBytes -= len(f) - 1
		return f, false
	}
	var best *stream
	for s := range c.ready {
		if best == nil || s.prio < best.prio || s.prio == best.prio && s.id < best.id {
			best = s
		}
	}
	if best == nil {
		return nil, false
	}
	n := min(len(best.pending), maxChunk)
	data := best.pending[:n]
	best.pending = best.pending[n:]
	fin := best.fin && len(best.pending) == 0
	f := appendStream(nil, best.id, fin, data)
	if len(best.pending) == 0 {
		best.pending = nil
		delete(c.ready, best)
	}
	if fin {
		best.sendDone = true
		c.maybeForget(best)
	}
	best.wake()
	return f, false
}

func (c *Conn) readLoop() {
	for {
		typ, b, err := c.ws.Read(context.Background())
		if err != nil {
			if c.ctx.Err() == nil {
				if websocket.CloseStatus(err) != -1 {
					err = io.EOF
				}
				c.shutdown(fmt.Errorf("ws: connection lost: %w", err))
			}
			return
		}
		if typ != websocket.MessageBinary {
			c.CloseWithError(errProtocolViolation, "text message")
			return
		}
		if err := c.handle(b); err != nil {
			c.CloseWithError(errProtocolViolation, err.Error())
			return
		}
	}
}

// errProtocolViolation is MOQT's PROTOCOL_VIOLATION, used for framing
// errors since the frames carry MOQT.
const errProtocolViolation = 0x3

func (c *Conn) handle(b []byte) error {
	f, err := parseFrame(b)
	if err != nil {
		return err
	}
	switch f.typ {
	case frameDatagram:
		select {
		case c.dgrams <- f.data:
		default:
		}
		return nil
	case frameClose:
		c.shutdown(&CloseError{Code: f.code, Reason: string(f.data), Remote: true})
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.peerStream(f.id, f.typ == frameStopSending)
	if err != nil || s == nil {
		return err
	}
	switch f.typ {
	case frameStream:
		if !s.canRecv {
			return errors.New("data on a send-only stream")
		}
		if s.recvDone || s.rerr != nil {
			return nil
		}
		if s.rfin {
			return errors.New("data after FIN")
		}
		if len(f.data) > 0 {
			s.chunks = append(s.chunks, f.data)
			c.unread += len(f.data)
			if c.unread > maxUnread {
				return errors.New("too much unread data")
			}
		}
		s.rfin = f.fin
		s.wake()
	case frameResetStream:
		if !s.canRecv {
			return errors.New("reset of a send-only stream")
		}
		if !s.recvDone && s.rerr == nil {
			c.dropUnread(s)
			s.rerr = &StreamError{Code: f.code, Remote: true}
			s.wake()
		}
	case frameStopSending:
		if !s.canSend {
			return errors.New("stop sending on a receive-only stream")
		}
		s.resetSend(f.code, &StreamError{Code: f.code, Remote: true})
	}
	return nil
}

// peerStream finds the stream a frame is for, opening it if the peer
// started it. It returns nil for streams that have been forgotten.
func (c *Conn) peerStream(id uint64, forSending bool) (*stream, error) {
	if s := c.streams[id]; s != nil {
		return s, nil
	}
	fromServer := id&1 == 1
	uni := id&2 == 2
	if fromServer != c.client {
		return nil, nil // ours, already finished
	}
	if uni && forSending {
		return nil, errors.New("stop sending on a receive-only stream")
	}
	kind := 0
	if uni {
		kind = 1
	}
	count := id >> 2
	if count < c.nextPeer[kind] {
		return nil, nil
	}
	// As in QUIC, a stream implicitly opens every lower one of its kind.
	var s *stream
	for ; c.nextPeer[kind] <= count; c.nextPeer[kind]++ {
		s = c.newStream(streamID(c.nextPeer[kind], uni, fromServer), !uni, true)
		c.streams[s.id] = s
		q := c.acceptBidi
		if uni {
			q = c.acceptUni
		}
		select {
		case q <- s:
		default:
			return nil, errors.New("too many streams")
		}
	}
	return s, nil
}

func (c *Conn) dropUnread(s *stream) {
	for _, b := range s.chunks {
		c.unread -= len(b)
	}
	s.chunks = nil
}

// maybeForget drops a stream once both halves are done.
func (c *Conn) maybeForget(s *stream) {
	if (!s.canSend || s.sendDone) && (!s.canRecv || s.recvDone) {
		delete(c.streams, s.id)
		delete(c.ready, s)
	}
}

func (c *Conn) newStream(id uint64, canSend, canRecv bool) *stream {
	// Control and request streams never set a priority: they go first.
	s := &stream{c: c, id: id, canSend: canSend, canRecv: canRecv, notify: make(chan struct{}, 1)}
	s.sctx, s.scancel = context.WithCancel(c.ctx)
	return s
}

// stream is one stream; the fields are guarded by c.mu.
type stream struct {
	c      *Conn
	id     uint64
	notify chan struct{}

	canSend  bool
	pending  []byte
	fin      bool  // Close called; the FIN follows the pending data
	sendDone bool  // FIN or RESET_STREAM queued
	werr     error // why writing stopped
	prio     uint8
	sctx     context.Context
	scancel  context.CancelFunc

	canRecv  bool
	chunks   [][]byte
	rfin     bool
	rerr     error
	recvDone bool // read to the end, cancelled or reset and seen
}

func (s *stream) wake() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// fail ends both halves with a connection error; c.mu is held.
func (s *stream) fail(err error) {
	if s.werr == nil {
		s.werr = err
	}
	if s.rerr == nil {
		s.rerr = err
	}
	s.pending = nil
	s.scancel()
	s.wake()
}

func (s *stream) Write(b []byte) (int, error) {
	c := s.c
	for {
		c.mu.Lock()
		switch {
		case s.werr != nil:
			c.mu.Unlock()
			return 0, s.werr
		case s.fin:
			c.mu.Unlock()
			return 0, errClosedStream
		case len(s.pending) < sendBuffer:
			s.pending = append(s.pending, b...)
			if len(b) > 0 {
				c.ready[s] = struct{}{}
			}
			c.mu.Unlock()
			c.signal()
			return len(b), nil
		}
		c.mu.Unlock()
		<-s.notify
	}
}

func (s *stream) Close() error {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.werr != nil || s.fin {
		return nil
	}
	s.fin = true
	c.ready[s] = struct{}{}
	s.scancel()
	c.signal()
	return nil
}

func (s *stream) CancelWrite(code uint64) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	s.resetSend(code, &StreamError{Code: code})
}

// resetSend drops unsent data and queues RESET_STREAM; c.mu is held.
func (s *stream) resetSend(code uint64, err error) {
	c := s.c
	if s.werr != nil || s.sendDone {
		return
	}
	s.werr = err
	s.pending = nil
	s.sendDone = true
	delete(c.ready, s)
	c.ctrl = append(c.ctrl, appendCode(nil, frameResetStream, s.id, code))
	s.scancel()
	s.wake()
	c.maybeForget(s)
	c.signal()
}

func (s *stream) SetPriority(p uint8) {
	s.c.mu.Lock()
	s.prio = p
	s.c.mu.Unlock()
}

func (s *stream) Context() context.Context { return s.sctx }

func (s *stream) Read(b []byte) (int, error) {
	c := s.c
	for {
		c.mu.Lock()
		if len(s.chunks) > 0 {
			n := 0
			for n < len(b) && len(s.chunks) > 0 {
				k := copy(b[n:], s.chunks[0])
				n += k
				if k == len(s.chunks[0]) {
					s.chunks = s.chunks[1:]
				} else {
					s.chunks[0] = s.chunks[0][k:]
				}
			}
			c.unread -= n
			c.mu.Unlock()
			return n, nil
		}
		if s.rerr != nil || s.rfin {
			err := s.rerr
			if err == nil {
				err = io.EOF
			}
			s.recvDone = true
			c.maybeForget(s)
			c.mu.Unlock()
			return 0, err
		}
		c.mu.Unlock()
		<-s.notify
	}
}

func (s *stream) CancelRead(code uint64) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.recvDone || s.rerr != nil {
		return
	}
	c.dropUnread(s)
	s.rerr = &StreamError{Code: code}
	s.recvDone = true
	if !s.rfin {
		c.ctrl = append(c.ctrl, appendCode(nil, frameStopSending, s.id, code))
		c.signal()
	}
	s.wake()
	c.maybeForget(s)
}
