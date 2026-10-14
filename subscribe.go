package moqt

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// ErrUnsubscribed is returned by a Subscription after Unsubscribe.
var ErrUnsubscribed = errors.New("moqt: unsubscribed")

// Subscribe subscribes to a track and waits for SUBSCRIBE_OK. A
// REQUEST_ERROR is returned as *RequestError.
func (s *Session) Subscribe(ctx context.Context, track v22.FullTrackName, params *v22.Params) (*Subscription, error) {
	if err := track.Validate(); err != nil {
		return nil, err
	}
	rs, err := s.openRequest(ctx)
	if err != nil {
		return nil, err
	}
	if params == nil {
		params = &v22.Params{}
	}
	if err := rs.send(&v22.Subscribe{RequestID: s.nextRequestID(), Track: track, Params: params}); err != nil {
		rs.cancel(v22.ResetInternalError)
		return nil, err
	}
	m, err := rs.recvCtx(ctx)
	if err != nil {
		return nil, err
	}
	switch m := m.(type) {
	case *v22.SubscribeOK:
		info, err := v22.ParseTrackInfo(m.TrackProperties)
		if err != nil {
			s.fail(err)
			return nil, err
		}
		sub := &Subscription{
			Track:      track,
			TrackAlias: m.TrackAlias,
			Info:       info,
			Properties: m.TrackProperties,
			s:          s,
			rs:         rs,
			subgroups:  make(chan *IncomingSubgroup, 64),
			datagrams:  make(chan *v22.Datagram, 256),
			notify:     make(chan *v22.Params, 8),
			done:       make(chan struct{}),

			streamArrived: make(chan struct{}),
		}
		if m.Params != nil {
			sub.LargestObject = m.Params.LargestObject
		}
		if err := s.registerAlias(m.TrackAlias, sub); err != nil {
			s.fail(err)
			return nil, err
		}
		go sub.readResponses()
		return sub, nil
	case *v22.RequestError:
		rs.finish()
		return nil, requestError(m)
	default:
		err := unexpected(m, "SUBSCRIBE response")
		s.fail(err)
		return nil, err
	}
}

// Subscription is the subscriber's side of an established subscription.
type Subscription struct {
	Track         v22.FullTrackName
	TrackAlias    uint64
	Info          v22.TrackInfo
	Properties    v22.KeyValues
	LargestObject *v22.Location // from SUBSCRIBE_OK, if the publisher knew it

	s         *Session
	rs        *requestStream
	subgroups chan *IncomingSubgroup
	datagrams chan *v22.Datagram
	notify    chan *v22.Params

	updMu      sync.Mutex
	updWaiters []chan v22.Message // REQUEST_UPDATE replies, in send order

	streamMu      sync.Mutex
	streamsSeen   uint64
	streamArrived chan struct{} // closed and replaced on each new data stream

	doneOnce sync.Once
	done     chan struct{}
	result   *v22.PublishDone
	err      error
}

func (sub *Subscription) readResponses() {
	for {
		m, err := sub.rs.recv()
		if err != nil {
			if err == io.EOF {
				err = errors.New("moqt: subscription stream closed without PUBLISH_DONE")
			}
			sub.finish(nil, err)
			return
		}
		switch m := m.(type) {
		case *v22.PublishDone:
			sub.rs.finish()
			sub.awaitStreams(m.StreamCount)
			sub.finish(m, nil)
			return
		case *v22.PublishStateNotify:
			select {
			case sub.notify <- m.Params:
			default:
			}
		case *v22.RequestOK, *v22.RequestError:
			sub.updMu.Lock()
			if len(sub.updWaiters) == 0 {
				sub.updMu.Unlock()
				sub.s.fail(unexpected(m, "subscription without a pending REQUEST_UPDATE"))
				return
			}
			w := sub.updWaiters[0]
			sub.updWaiters = sub.updWaiters[1:]
			sub.updMu.Unlock()
			w <- m
		default:
			sub.s.fail(unexpected(m, "subscription"))
			return
		}
	}
}

// lateStreamWait bounds how long a subscription waits after PUBLISH_DONE
// for data streams still in flight (Section 9.9).
const lateStreamWait = 2 * time.Second

// awaitStreams waits until the publisher's Stream Count of data streams has
// arrived, since PUBLISH_DONE can overtake them, or until lateStreamWait.
func (sub *Subscription) awaitStreams(count uint64) {
	timer := time.NewTimer(lateStreamWait)
	defer timer.Stop()
	for {
		sub.streamMu.Lock()
		n, ch := sub.streamsSeen, sub.streamArrived
		sub.streamMu.Unlock()
		if count != v22.StreamCountUnknown && n >= count {
			return
		}
		select {
		case <-ch:
		case <-timer.C:
			return
		case <-sub.s.ctx.Done():
			return
		}
	}
}

func (sub *Subscription) finish(result *v22.PublishDone, err error) {
	sub.doneOnce.Do(func() {
		sub.result, sub.err = result, err
		close(sub.done)
		sub.s.releaseAlias(sub.TrackAlias, sub)
	})
}

// Done is closed when the subscription ends: PUBLISH_DONE, Unsubscribe or
// a stream failure. Objects already in flight may still be delivered for
// a short while afterwards.
func (sub *Subscription) Done() <-chan struct{} { return sub.done }

// Result returns the PUBLISH_DONE that ended the subscription, or the error.
func (sub *Subscription) Result() (*v22.PublishDone, error) {
	select {
	case <-sub.done:
		return sub.result, sub.err
	default:
		return nil, nil
	}
}

// StateNotifications delivers PUBLISH_STATE_NOTIFY parameters.
func (sub *Subscription) StateNotifications() <-chan *v22.Params { return sub.notify }

func (sub *Subscription) deliverSubgroup(g *IncomingSubgroup) {
	sub.streamMu.Lock()
	sub.streamsSeen++
	close(sub.streamArrived)
	sub.streamArrived = make(chan struct{})
	sub.streamMu.Unlock()
	select {
	case <-sub.done:
		if sub.err == ErrUnsubscribed {
			g.Cancel()
			return
		}
	default:
	}
	select {
	case sub.subgroups <- g:
	default:
		g.Cancel() // the application is not keeping up
	}
}

func (sub *Subscription) deliverDatagram(d *v22.Datagram) {
	select {
	case sub.datagrams <- d:
	default:
	}
}

// AcceptSubgroup returns the next subgroup stream of the track.
func (sub *Subscription) AcceptSubgroup(ctx context.Context) (*IncomingSubgroup, error) {
	select {
	case g := <-sub.subgroups:
		return g, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-sub.done:
		select {
		case g := <-sub.subgroups:
			return g, nil
		default:
		}
		if sub.err != nil {
			return nil, sub.err
		}
		return nil, io.EOF
	}
}

// ReceiveDatagram returns the next Object sent as a datagram.
func (sub *Subscription) ReceiveDatagram(ctx context.Context) (*v22.Datagram, error) {
	select {
	case d := <-sub.datagrams:
		return d, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-sub.done:
		if sub.err != nil {
			return nil, sub.err
		}
		return nil, io.EOF
	}
}

// Update sends REQUEST_UPDATE (e.g. SUBSCRIBER_PRIORITY, FORWARD,
// NEW_GROUP_REQUEST) and waits for the publisher's answer.
func (sub *Subscription) Update(ctx context.Context, params *v22.Params) error {
	w := make(chan v22.Message, 1)
	sub.updMu.Lock()
	sub.updWaiters = append(sub.updWaiters, w)
	err := sub.rs.send(&v22.RequestUpdate{RequestID: sub.s.nextRequestID(), Params: params})
	sub.updMu.Unlock()
	if err != nil {
		return err
	}
	select {
	case m := <-w:
		if e, ok := m.(*v22.RequestError); ok {
			return requestError(e)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-sub.done:
		if sub.err != nil {
			return sub.err
		}
		return io.EOF
	}
}

// Unsubscribe cancels the subscription.
func (sub *Subscription) Unsubscribe() {
	// Record the reason before cancelling, or the reader goroutine may see
	// the cancelled stream first and report that instead.
	sub.finish(nil, ErrUnsubscribed)
	sub.rs.cancel(v22.ResetCancelled)
}

// IncomingSubgroup is a subgroup stream being received.
type IncomingSubgroup struct {
	Header *v22.SubgroupHeader
	r      *v22.SubgroupReader
	str    ReceiveStream
	s      *Session

	idKnown    bool
	subgroupID uint64
}

// SubgroupID returns the Subgroup ID. With SubgroupIDFirstObject it is
// known only after the first Object has been read.
func (g *IncomingSubgroup) SubgroupID() (uint64, bool) {
	switch g.Header.IDMode {
	case v22.SubgroupIDZero:
		return 0, true
	case v22.SubgroupIDExplicit:
		return g.Header.SubgroupID, true
	}
	return g.subgroupID, g.idKnown
}

// Next returns the next Object, or io.EOF when the subgroup is complete.
// Protocol violations close the session.
func (g *IncomingSubgroup) Next() (*v22.Object, error) {
	o, err := g.r.Next()
	if err != nil {
		var se *v22.SessionError
		if errors.As(err, &se) {
			g.s.fail(se)
		}
		return nil, err
	}
	if !g.idKnown {
		g.idKnown, g.subgroupID = true, o.ID
	}
	return o, nil
}

// Cancel stops receiving the subgroup (STOP_SENDING).
func (g *IncomingSubgroup) Cancel() { g.str.CancelRead(uint64(v22.ResetCancelled)) }

// SubscribeRequest is an incoming SUBSCRIBE.
type SubscribeRequest struct {
	RequestID uint64
	Track     v22.FullTrackName
	Params    *v22.Params

	s  *Session
	rs *requestStream
}

// Reject answers with REQUEST_ERROR.
func (r *SubscribeRequest) Reject(code v22.RequestErrorCode, reason string) error {
	return r.rs.reject(code, reason)
}

// AcceptOptions are the publisher's answer to a SUBSCRIBE.
type AcceptOptions struct {
	// Properties are the Track Properties, e.g. DEFAULT PUBLISHER PRIORITY
	// and DYNAMIC GROUPS.
	Properties    v22.KeyValues
	LargestObject *v22.Location
	Expires       *uint64 // ms
}

// Accept answers with SUBSCRIBE_OK and returns the writer for the track.
func (r *SubscribeRequest) Accept(opts AcceptOptions) (*TrackWriter, error) {
	info, err := v22.ParseTrackInfo(opts.Properties)
	if err != nil {
		return nil, err
	}
	alias := r.s.nextAlias.Add(1) - 1
	ok := &v22.SubscribeOK{
		TrackAlias:      alias,
		Params:          &v22.Params{LargestObject: opts.LargestObject, Expires: opts.Expires},
		TrackProperties: opts.Properties,
	}
	if err := r.rs.send(ok); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(r.s.ctx)
	w := &TrackWriter{
		Track:      r.Track,
		TrackAlias: alias,
		Info:       info,
		s:          r.s,
		rs:         r.rs,
		ctx:        ctx,
		cancel:     cancel,
		updates:    make(chan *v22.Params, 16),
		forward:    true, // FORWARD defaults to 1 (Section 9.20.18)
	}
	w.applyParams(r.Params)
	go w.readRequests()
	return w, nil
}

// ErrSubscriberGone is the cause of a TrackWriter's context once the
// subscriber cancels.
var ErrSubscriberGone = errors.New("moqt: subscriber cancelled")

// TrackWriter is the publisher's side of an established subscription.
type TrackWriter struct {
	Track      v22.FullTrackName
	TrackAlias uint64
	Info       v22.TrackInfo

	s       *Session
	rs      *requestStream
	ctx     context.Context
	cancel  context.CancelCauseFunc
	streams atomic.Uint64
	updates chan *v22.Params

	mu                 sync.Mutex
	subscriberPriority *uint8
	forward            bool
	closed             bool
}

// applyParams applies the parameters present in a SUBSCRIBE or
// REQUEST_UPDATE; absent ones keep their value (Section 9.5).
func (w *TrackWriter) applyParams(p *v22.Params) {
	if p == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if p.SubscriberPriority != nil {
		w.subscriberPriority = p.SubscriberPriority
	}
	if p.Forward != nil {
		w.forward = *p.Forward == 1
	}
}

func (w *TrackWriter) readRequests() {
	for {
		m, err := w.rs.recv()
		if err == io.EOF {
			return // the subscriber will send no REQUEST_UPDATE; not a cancel
		}
		if err != nil {
			w.cancel(ErrSubscriberGone)
			return
		}
		u, ok := m.(*v22.RequestUpdate)
		if !ok {
			w.s.fail(unexpected(m, "subscription from subscriber"))
			return
		}
		if !w.s.checkPeerRequestID(u.RequestID) {
			return
		}
		w.applyParams(u.Params)
		select {
		case w.updates <- u.Params:
		default:
		}
		if err := w.rs.send(&v22.RequestOK{Params: &v22.Params{}}); err != nil {
			w.cancel(err)
			return
		}
	}
}

// Context is cancelled when the subscriber cancels or the session ends.
func (w *TrackWriter) Context() context.Context { return w.ctx }

// Updates delivers the parameters of each REQUEST_UPDATE, which has
// already been acknowledged. NEW_GROUP_REQUEST arrives this way.
func (w *TrackWriter) Updates() <-chan *v22.Params { return w.updates }

// Forwarding reports whether the subscriber wants Objects (FORWARD).
func (w *TrackWriter) Forwarding() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.forward
}

// priority picks the stream priority: the subscriber's priority when it
// set one, which orders tracks within the session (Section 5.1), else the
// publisher's.
func (w *TrackWriter) priority(publisher uint8) uint8 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.subscriberPriority != nil {
		return *w.subscriberPriority
	}
	return publisher
}

// SubgroupOptions describe a subgroup stream.
type SubgroupOptions struct {
	// Priority overrides the track's default publisher priority.
	Priority    *uint8
	Properties  bool // Objects carry Object Properties
	EndOfGroup  bool // the subgroup holds the Group's last Object
	FirstObject bool // the stream starts at the subgroup's first Object
}

// OpenSubgroup starts a subgroup. The stream is opened by the first
// WriteObject, so a subgroup with no Objects never becomes an empty
// stream (an empty FIN'd stream kills Firefox's WebTransport session).
func (w *TrackWriter) OpenSubgroup(group, subgroupID uint64, opts SubgroupOptions) *OutgoingSubgroup {
	hdr := &v22.SubgroupHeader{
		TrackAlias:  w.TrackAlias,
		Group:       group,
		IDMode:      v22.SubgroupIDExplicit,
		SubgroupID:  subgroupID,
		Properties:  opts.Properties,
		EndOfGroup:  opts.EndOfGroup,
		FirstObject: opts.FirstObject,
	}
	if subgroupID == 0 {
		hdr.IDMode = v22.SubgroupIDZero
	}
	prio := w.Info.PublisherPriority
	if opts.Priority != nil {
		hdr.HasPriority, hdr.Priority = true, *opts.Priority
		prio = *opts.Priority
	}
	return &OutgoingSubgroup{w: w, enc: v22.SubgroupWriter{Header: hdr}, prio: prio}
}

// WriteDatagram sends an Object as a datagram on this track.
func (w *TrackWriter) WriteDatagram(d *v22.Datagram) error {
	d.TrackAlias = w.TrackAlias
	b, err := v22.AppendDatagram(nil, d)
	if err != nil {
		return err
	}
	return w.s.conn.SendDatagram(b)
}

// Close ends the subscription with PUBLISH_DONE. Call it only after every
// subgroup stream has been closed or reset.
func (w *TrackWriter) Close(code v22.PublishDoneCode, reason string) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()
	err := w.rs.send(&v22.PublishDone{StatusCode: code, StreamCount: w.streams.Load(), Reason: reason})
	w.rs.finish()
	w.cancel(errors.New("moqt: publish done"))
	return err
}

// OutgoingSubgroup is a subgroup stream being sent.
type OutgoingSubgroup struct {
	w    *TrackWriter
	enc  v22.SubgroupWriter
	prio uint8
	buf  []byte

	// str is set by the first WriteObject; Reset may run concurrently with
	// a blocked write (delivery timeouts), so it is guarded.
	mu    sync.Mutex
	str   SendStream
	reset bool
}

// ErrSubgroupReset is returned by WriteObject after Reset.
var ErrSubgroupReset = errors.New("moqt: subgroup reset")

// WriteObject sends one Object; IDs must increase.
func (g *OutgoingSubgroup) WriteObject(o *v22.Object) error {
	g.mu.Lock()
	if g.reset {
		g.mu.Unlock()
		return ErrSubgroupReset
	}
	str := g.str
	g.mu.Unlock()
	if str == nil {
		var err error
		if str, err = g.w.s.conn.OpenUniStreamSync(g.w.ctx); err != nil {
			return err
		}
		str.SetPriority(g.w.priority(g.prio))
		g.w.streams.Add(1)
		g.mu.Lock()
		g.str = str
		reset := g.reset
		g.mu.Unlock()
		if reset {
			str.CancelWrite(uint64(v22.ResetCancelled))
			return ErrSubgroupReset
		}
		g.buf = g.enc.Header.Append(g.buf[:0])
	}
	var err error
	if g.buf, err = g.enc.AppendObject(g.buf, o); err != nil {
		return err
	}
	_, err = str.Write(g.buf)
	g.buf = g.buf[:0]
	return err
}

// Close ends the subgroup with a FIN after its last Object.
func (g *OutgoingSubgroup) Close() error {
	g.mu.Lock()
	str := g.str
	g.mu.Unlock()
	if str == nil {
		return nil
	}
	return str.Close()
}

// Reset abandons the subgroup, e.g. on a delivery timeout. It is safe to
// call while WriteObject is blocked, which it then unblocks.
func (g *OutgoingSubgroup) Reset(code v22.StreamResetCode) {
	g.mu.Lock()
	g.reset = true
	str := g.str
	g.mu.Unlock()
	if str != nil {
		str.CancelWrite(uint64(code))
	}
}
