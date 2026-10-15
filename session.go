package moqt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// Role is the endpoint's side of the session; it fixes Request ID parity.
type Role uint8

const (
	Client Role = iota // even Request IDs
	Server             // odd Request IDs
)

// Implementation is sent in the MOQT_IMPLEMENTATION setup option.
const Implementation = "moqt-go/0.1 (draft-22)"

// Handler receives requests the peer initiates. Each call runs on its own
// goroutine and must answer the request with Accept or Reject.
type Handler interface {
	HandleSubscribe(r *SubscribeRequest)
	HandlePublishNamespace(r *PublishNamespaceRequest)
	HandleSubscribeNamespace(r *SubscribeNamespaceRequest)
}

// RejectAll answers every request with NOT_SUPPORTED. Embed it to handle
// only some request types.
type RejectAll struct{}

func (RejectAll) HandleSubscribe(r *SubscribeRequest) { r.Reject(v22.ReqErrNotSupported, "") }
func (RejectAll) HandlePublishNamespace(r *PublishNamespaceRequest) {
	r.Reject(v22.ReqErrNotSupported, "")
}
func (RejectAll) HandleSubscribeNamespace(r *SubscribeNamespaceRequest) {
	r.Reject(v22.ReqErrNotSupported, "")
}

// Config configures a session.
type Config struct {
	Handler Handler
	// SetupOptions are sent in SETUP in addition to MOQT_IMPLEMENTATION,
	// e.g. AUTHORIZATION TOKEN, or PATH and AUTHORITY over raw QUIC.
	SetupOptions v22.KeyValues
	// CheckSetup validates the peer's SETUP before any of its requests are
	// handled. A *v22.SessionError picks the close code; any other error
	// closes the session with UNAUTHORIZED.
	CheckSetup func(*v22.Setup) error
	// SetupTimeout bounds the wait for the peer's SETUP (default 10s).
	SetupTimeout time.Duration
	// AliasWait is how long a data stream with an unknown Track Alias is
	// held for its SUBSCRIBE_OK to arrive (default 2s, Section 3.1.3.1).
	AliasWait time.Duration
	Logger    *slog.Logger
}

// Session is one MOQT session.
type Session struct {
	conn   Conn
	role   Role
	cfg    Config
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelCauseFunc

	ctrlMu sync.Mutex
	ctrl   SendStream

	peerSetupCh chan struct{}
	peerSetup   *v22.Setup
	ready       chan struct{} // peer SETUP received and accepted

	nextReqID atomic.Uint64
	nextAlias atomic.Uint64

	mu        sync.Mutex
	gotCtrl   bool
	peerIDs   idSet
	subs      map[uint64]*Subscription // by Track Alias
	aliasWait map[uint64]chan struct{}
	fetches   map[uint64]*IncomingFetch // by Request ID
	goaway    *v22.Goaway
	goawayCh  chan struct{}
	closeOnce sync.Once
}

// NewSession starts a session on conn: it sends SETUP and returns once the
// peer's SETUP has arrived and passed Config.CheckSetup.
func NewSession(ctx context.Context, conn Conn, role Role, cfg Config) (*Session, error) {
	if cfg.Handler == nil {
		cfg.Handler = RejectAll{}
	}
	if cfg.SetupTimeout == 0 {
		cfg.SetupTimeout = 10 * time.Second
	}
	if cfg.AliasWait == 0 {
		cfg.AliasWait = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Session{
		conn:        conn,
		role:        role,
		cfg:         cfg,
		log:         cfg.Logger,
		peerSetupCh: make(chan struct{}),
		ready:       make(chan struct{}),
		subs:        map[uint64]*Subscription{},
		aliasWait:   map[uint64]chan struct{}{},
		fetches:     map[uint64]*IncomingFetch{},
		goawayCh:    make(chan struct{}),
	}
	s.ctx, s.cancel = context.WithCancelCause(conn.Context())
	if role == Server {
		s.nextReqID.Store(1)
		s.peerIDs.next = 0
	} else {
		s.peerIDs.next = 1
	}

	ctrl, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("opening control stream: %w", err)
	}
	s.ctrl = ctrl
	opts := append(v22.KeyValues{{Type: v22.OptMOQTImplementation, Bytes: []byte(Implementation)}}, cfg.SetupOptions...)
	if err := s.writeControl(&v22.Setup{Options: opts}); err != nil {
		return nil, err
	}

	go s.acceptUniStreams()
	go s.acceptRequests()
	go s.receiveDatagrams()

	timer := time.NewTimer(cfg.SetupTimeout)
	defer timer.Stop()
	select {
	case <-s.peerSetupCh:
	case <-timer.C:
		s.CloseWithError(v22.ErrControlMessageTimeout, "no SETUP")
		return nil, errors.New("moqt: timed out waiting for SETUP")
	case <-ctx.Done():
		s.CloseWithError(v22.ErrInternal, "cancelled")
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.Err()
	}
	if cfg.CheckSetup != nil {
		if err := cfg.CheckSetup(s.peerSetup); err != nil {
			var se *v22.SessionError
			if !errors.As(err, &se) {
				se = &v22.SessionError{Code: v22.ErrUnauthorized, Reason: err.Error()}
			}
			s.CloseWithError(se.Code, se.Reason)
			return nil, se
		}
	}
	close(s.ready)
	return s, nil
}

// PeerSetup returns the peer's SETUP message.
func (s *Session) PeerSetup() *v22.Setup { return s.peerSetup }

// Context is cancelled when the session ends; context.Cause gives why.
func (s *Session) Context() context.Context { return s.ctx }

// Err reports why the session ended, or nil while it is open.
func (s *Session) Err() error {
	if s.ctx.Err() == nil {
		return nil
	}
	return context.Cause(s.ctx)
}

// CloseWithError closes the session.
func (s *Session) CloseWithError(code v22.SessionErrorCode, reason string) error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel(&v22.SessionError{Code: code, Reason: reason})
		err = s.conn.CloseWithError(uint64(code), reason)
	})
	return err
}

// Close closes the session with NO_ERROR.
func (s *Session) Close() error { return s.CloseWithError(v22.ErrNoError, "") }

// fail closes the session because of err, using its code if it is a
// *v22.SessionError. Errors after the session has ended are ignored.
func (s *Session) fail(err error) {
	if s.ctx.Err() != nil {
		return
	}
	var se *v22.SessionError
	if !errors.As(err, &se) {
		se = &v22.SessionError{Code: v22.ErrInternal, Reason: err.Error()}
	}
	s.log.Warn("closing session", "code", uint64(se.Code), "reason", se.Reason)
	s.CloseWithError(se.Code, se.Reason)
}

// GoAway sends GOAWAY on the control stream. Only a server may give a new
// session URI.
func (s *Session) GoAway(newSessionURI string, timeout time.Duration) error {
	if s.role == Client && newSessionURI != "" {
		return errors.New("moqt: a client GOAWAY cannot carry a URI")
	}
	return s.writeControl(&v22.Goaway{NewSessionURI: newSessionURI, Timeout: uint64(timeout.Milliseconds())})
}

// GoAwayReceived is closed when the peer sends GOAWAY; PeerGoAway then
// returns it.
func (s *Session) GoAwayReceived() <-chan struct{} { return s.goawayCh }

func (s *Session) PeerGoAway() *v22.Goaway {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goaway
}

func (s *Session) writeControl(m v22.Message) error {
	b, err := v22.AppendMessage(nil, m)
	if err != nil {
		return err
	}
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	_, err = s.ctrl.Write(b)
	return err
}

func (s *Session) nextRequestID() uint64 { return s.nextReqID.Add(2) - 2 }

func (s *Session) waitReady(ctx context.Context) error {
	select {
	case <-s.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.Err()
	}
}

func (s *Session) acceptUniStreams() {
	for {
		str, err := s.conn.AcceptUniStream(s.ctx)
		if err != nil {
			s.cancel(err)
			return
		}
		go s.handleUniStream(str)
	}
}

func (s *Session) handleUniStream(str ReceiveStream) {
	br := bufio.NewReader(str)
	typ, err := v22.ReadVarint(br)
	if err != nil {
		return // reset before the type arrived
	}
	switch {
	case typ == v22.StreamTypeSetup:
		s.readControlStream(br)
	case v22.IsSubgroupStreamType(typ):
		select {
		case <-s.ready:
		case <-s.ctx.Done():
			return
		}
		s.handleSubgroupStream(str, br, typ)
	case typ == v22.StreamTypeFetch:
		select {
		case <-s.ready:
		case <-s.ctx.Done():
			return
		}
		s.handleFetchStream(str, br)
	case typ == v22.StreamTypePadding:
		io.Copy(io.Discard, br)
	default:
		s.fail(&v22.SessionError{Code: v22.ErrProtocolViolation, Reason: fmt.Sprintf("unknown stream type 0x%x", typ)})
	}
}

func (s *Session) readControlStream(br *bufio.Reader) {
	s.mu.Lock()
	dup := s.gotCtrl
	s.gotCtrl = true
	s.mu.Unlock()
	if dup {
		s.fail(&v22.SessionError{Code: v22.ErrProtocolViolation, Reason: "second control stream"})
		return
	}
	m, err := v22.ReadMessageBody(br, v22.MsgSetup)
	if err != nil {
		s.fail(asViolation(err, "reading SETUP"))
		return
	}
	s.peerSetup = m.(*v22.Setup)
	if s.role == Server && s.conn.WebTransport() {
		for _, opt := range s.peerSetup.Options {
			if opt.Type == v22.OptPath || opt.Type == v22.OptAuthority {
				code := v22.ErrInvalidPath
				if opt.Type == v22.OptAuthority {
					code = v22.ErrInvalidAuthority
				}
				s.fail(&v22.SessionError{Code: code, Reason: "PATH/AUTHORITY over WebTransport"})
				return
			}
		}
	}
	close(s.peerSetupCh)
	for {
		m, err := v22.ReadMessage(br)
		if err != nil {
			var se *v22.SessionError
			if err == io.EOF || err == io.ErrUnexpectedEOF || errors.As(err, &se) {
				// The peer closed its control stream or sent garbage.
				s.fail(asViolation(err, "control stream"))
			} else {
				// A transport error: the session is being torn down, which
				// can surface here before the connection's context ends.
				s.cancel(err)
			}
			return
		}
		g, ok := m.(*v22.Goaway)
		if !ok {
			s.fail(&v22.SessionError{Code: v22.ErrProtocolViolation, Reason: fmt.Sprintf("message 0x%x on control stream", uint64(m.Type()))})
			return
		}
		if s.role == Server && g.NewSessionURI != "" {
			s.fail(&v22.SessionError{Code: v22.ErrProtocolViolation, Reason: "client GOAWAY with a URI"})
			return
		}
		s.mu.Lock()
		dup := s.goaway != nil
		if !dup {
			s.goaway = g
			close(s.goawayCh)
		}
		s.mu.Unlock()
		if dup {
			s.fail(&v22.SessionError{Code: v22.ErrProtocolViolation, Reason: "second GOAWAY"})
			return
		}
	}
}

// asViolation turns stream-level failures on streams that must stay open
// into a protocol violation, keeping session errors from the decoder.
func asViolation(err error, where string) error {
	var se *v22.SessionError
	if errors.As(err, &se) {
		return se
	}
	return &v22.SessionError{Code: v22.ErrProtocolViolation, Reason: where + ": " + err.Error()}
}

func (s *Session) acceptRequests() {
	for {
		str, err := s.conn.AcceptStream(s.ctx)
		if err != nil {
			s.cancel(err)
			return
		}
		go s.handleRequestStream(str)
	}
}

func (s *Session) handleRequestStream(str Stream) {
	select {
	case <-s.ready:
	case <-s.ctx.Done():
		return
	}
	rs := newRequestStream(s, str)
	m, err := rs.recv()
	if err != nil {
		rs.cancel(v22.ResetCancelled)
		return
	}
	if !m.Type().IsRequest() {
		s.fail(&v22.SessionError{Code: v22.ErrProtocolViolation, Reason: fmt.Sprintf("request stream starts with 0x%x", uint64(m.Type()))})
		return
	}
	if !s.checkPeerRequestID(requestIDOf(m)) {
		return
	}
	switch m := m.(type) {
	case *v22.Subscribe:
		s.cfg.Handler.HandleSubscribe(&SubscribeRequest{RequestID: m.RequestID, Track: m.Track, Params: m.Params, s: s, rs: rs})
	case *v22.PublishNamespace:
		s.cfg.Handler.HandlePublishNamespace(&PublishNamespaceRequest{RequestID: m.RequestID, Prefix: m.Prefix, Params: m.Params, rs: rs})
	case *v22.SubscribeNamespace:
		s.cfg.Handler.HandleSubscribeNamespace(&SubscribeNamespaceRequest{RequestID: m.RequestID, Prefix: m.Prefix, Params: m.Params, rs: rs})
	case *v22.Fetch:
		h, ok := s.cfg.Handler.(FetchHandler)
		if !ok {
			rs.reject(v22.ReqErrNotSupported, "not implemented")
			return
		}
		h.HandleFetch(&FetchRequest{RequestID: m.RequestID, Track: m.Track, Params: m.Params, s: s, rs: rs})
	default:
		rs.reject(v22.ReqErrNotSupported, "not implemented")
	}
}

func requestIDOf(m v22.Message) uint64 {
	switch m := m.(type) {
	case *v22.Subscribe:
		return m.RequestID
	case *v22.Publish:
		return m.RequestID
	case *v22.Fetch:
		return m.RequestID
	case *v22.TrackStatus:
		return m.RequestID
	case *v22.PublishNamespace:
		return m.RequestID
	case *v22.SubscribeNamespace:
		return m.RequestID
	case *v22.SubscribeTracks:
		return m.RequestID
	case *v22.RequestUpdate:
		return m.RequestID
	}
	return 0
}

// checkPeerRequestID enforces Section 6.4.2.1: the peer's parity and no
// duplicates. It closes the session and returns false on a violation.
func (s *Session) checkPeerRequestID(id uint64) bool {
	s.mu.Lock()
	ok := s.peerIDs.add(id)
	s.mu.Unlock()
	if !ok {
		s.fail(&v22.SessionError{Code: v22.ErrInvalidRequestID, Reason: fmt.Sprintf("request ID %d", id)})
	}
	return ok
}

// idSet records the peer's Request IDs. IDs arrive out of order across
// streams, so it keeps a low-water mark plus the IDs seen above it.
type idSet struct {
	next  uint64 // lowest ID not yet seen; parity of the peer
	above map[uint64]struct{}
}

func (t *idSet) add(id uint64) bool {
	if id%2 != t.next%2 || id < t.next {
		return false
	}
	if _, dup := t.above[id]; dup {
		return false
	}
	if id != t.next {
		if t.above == nil {
			t.above = map[uint64]struct{}{}
		}
		t.above[id] = struct{}{}
		return true
	}
	t.next += 2
	for {
		if _, ok := t.above[t.next]; !ok {
			return true
		}
		delete(t.above, t.next)
		t.next += 2
	}
}

func (s *Session) receiveDatagrams() {
	for {
		b, err := s.conn.ReceiveDatagram(s.ctx)
		if err != nil {
			return
		}
		select {
		case <-s.ready:
		default:
			continue // before SETUP completes nothing can be subscribed
		}
		dg, err := v22.ParseDatagram(b)
		if errors.Is(err, v22.ErrPaddingDatagram) {
			continue
		}
		if err != nil {
			s.fail(err)
			return
		}
		s.mu.Lock()
		sub := s.subs[dg.TrackAlias]
		s.mu.Unlock()
		if sub != nil {
			sub.deliverDatagram(dg)
		}
	}
}

func (s *Session) handleSubgroupStream(str ReceiveStream, br *bufio.Reader, typ uint64) {
	hdr, err := v22.ReadSubgroupHeader(br, typ)
	if err != nil {
		var se *v22.SessionError
		if errors.As(err, &se) {
			s.fail(se)
		}
		return
	}
	sub := s.waitSubscription(hdr.TrackAlias)
	if sub == nil {
		str.CancelRead(uint64(v22.ResetCancelled))
		return
	}
	sub.deliverSubgroup(&IncomingSubgroup{Header: hdr, r: v22.NewSubgroupReader(br, hdr), str: str, s: s})
}

// waitSubscription finds the subscription for a Track Alias, waiting up to
// AliasWait for a racing SUBSCRIBE_OK.
func (s *Session) waitSubscription(alias uint64) *Subscription {
	s.mu.Lock()
	if sub := s.subs[alias]; sub != nil {
		s.mu.Unlock()
		return sub
	}
	ch := s.aliasWait[alias]
	if ch == nil {
		ch = make(chan struct{})
		s.aliasWait[alias] = ch
	}
	s.mu.Unlock()
	timer := time.NewTimer(s.cfg.AliasWait)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	case <-s.ctx.Done():
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aliasWait[alias] == ch && s.subs[alias] == nil {
		delete(s.aliasWait, alias)
	}
	return s.subs[alias]
}

func (s *Session) registerAlias(alias uint64, sub *Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subs[alias] != nil {
		return &v22.SessionError{Code: v22.ErrDuplicateTrackAlias, Reason: fmt.Sprintf("track alias %d", alias)}
	}
	s.subs[alias] = sub
	if ch := s.aliasWait[alias]; ch != nil {
		close(ch)
		delete(s.aliasWait, alias)
	}
	return nil
}

// releaseAlias forgets a finished subscription after a grace period in
// which late Objects are still recognised and discarded (Section 3.1.3).
func (s *Session) releaseAlias(alias uint64, sub *Subscription) {
	time.AfterFunc(30*time.Second, func() {
		s.mu.Lock()
		if s.subs[alias] == sub {
			delete(s.subs, alias)
		}
		s.mu.Unlock()
	})
}

// requestStream is one bidirectional request stream.
type requestStream struct {
	s   *Session
	str Stream
	br  *bufio.Reader
	wmu sync.Mutex
}

func newRequestStream(s *Session, str Stream) *requestStream {
	return &requestStream{s: s, str: str, br: bufio.NewReader(str)}
}

func (s *Session) openRequest(ctx context.Context) (*requestStream, error) {
	if err := s.waitReady(ctx); err != nil {
		return nil, err
	}
	str, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return newRequestStream(s, str), nil
}

func (r *requestStream) send(m v22.Message) error {
	b, err := v22.AppendMessage(nil, m)
	if err != nil {
		return err
	}
	r.wmu.Lock()
	defer r.wmu.Unlock()
	_, err = r.str.Write(b)
	return err
}

// recv reads the next message. Decoding failures close the session.
func (r *requestStream) recv() (v22.Message, error) {
	m, err := v22.ReadMessage(r.br)
	if err != nil {
		var se *v22.SessionError
		if errors.As(err, &se) {
			r.s.fail(se)
		}
		return nil, err
	}
	return m, nil
}

// recvCtx is recv that gives up, cancelling the stream, when ctx ends.
func (r *requestStream) recvCtx(ctx context.Context) (v22.Message, error) {
	stop := context.AfterFunc(ctx, func() { r.cancel(v22.ResetCancelled) })
	defer stop()
	m, err := r.recv()
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return m, err
}

// finish sends FIN: no more messages in this direction.
func (r *requestStream) finish() { r.str.Close() }

// cancel abandons the request in both directions (Section 6.4.2.3).
func (r *requestStream) cancel(code v22.StreamResetCode) {
	r.str.CancelWrite(uint64(code))
	r.str.CancelRead(uint64(code))
}

func (r *requestStream) reject(code v22.RequestErrorCode, reason string) error {
	err := r.send(&v22.RequestError{Code: code, Reason: reason})
	r.finish()
	return err
}

// RequestError is a REQUEST_ERROR from the peer.
type RequestError struct {
	Code          v22.RequestErrorCode
	RetryInterval uint64
	Reason        string
	Redirect      *v22.Redirect
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("moqt: request rejected (0x%x): %s", uint64(e.Code), e.Reason)
}

func requestError(m *v22.RequestError) *RequestError {
	return &RequestError{Code: m.Code, RetryInterval: m.RetryInterval, Reason: m.Reason, Redirect: m.Redirect}
}

func unexpected(m v22.Message, where string) error {
	return &v22.SessionError{Code: v22.ErrProtocolViolation, Reason: fmt.Sprintf("unexpected 0x%x in %s", uint64(m.Type()), where)}
}
