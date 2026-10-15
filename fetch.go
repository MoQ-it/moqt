package moqt

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sync"

	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// FetchHandler is implemented by a Handler that answers FETCH. Without it,
// FETCH is answered with NOT_SUPPORTED.
type FetchHandler interface {
	HandleFetch(r *FetchRequest)
}

// ErrFetchCancelled is returned by an IncomingFetch after Cancel.
var ErrFetchCancelled = errors.New("moqt: fetch cancelled")

// Fetch requests already-published Objects, selected by params (typically
// a LOCATION_FILTER), and waits for FETCH_OK. A REQUEST_ERROR is returned
// as *RequestError.
func (s *Session) Fetch(ctx context.Context, track v22.FullTrackName, params *v22.Params) (*IncomingFetch, error) {
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
	f := &IncomingFetch{
		Track:     track,
		RequestID: s.nextRequestID(),
		s:         s,
		rs:        rs,
		stream:    make(chan *fetchStream, 1),
		done:      make(chan struct{}),
	}
	// Registered before FETCH is sent, so its data stream always finds it.
	s.mu.Lock()
	s.fetches[f.RequestID] = f
	s.mu.Unlock()
	if err := rs.send(&v22.Fetch{RequestID: f.RequestID, Track: track, Params: params}); err != nil {
		rs.cancel(v22.ResetInternalError)
		f.finish(err)
		return nil, err
	}
	m, err := rs.recvCtx(ctx)
	if err != nil {
		f.finish(err)
		return nil, err
	}
	switch m := m.(type) {
	case *v22.FetchOK:
		info, err := v22.ParseTrackInfo(m.TrackProperties)
		if err != nil {
			s.fail(err)
			f.finish(err)
			return nil, err
		}
		f.EndOfTrack, f.EndLocation, f.Properties = m.EndOfTrack, m.EndLocation, m.TrackProperties
		f.order = info.GroupOrder
		if params.GroupOrder != nil {
			f.order = *params.GroupOrder
		}
		go f.drainRequest()
		return f, nil
	case *v22.RequestError:
		rs.finish()
		err := requestError(m)
		f.finish(err)
		return nil, err
	default:
		err := unexpected(m, "FETCH response")
		s.fail(err)
		f.finish(err)
		return nil, err
	}
}

// IncomingFetch is the requester's side of an accepted fetch.
type IncomingFetch struct {
	Track       v22.FullTrackName
	RequestID   uint64
	EndOfTrack  bool
	EndLocation v22.Location // the largest Location the fetch covers
	Properties  v22.KeyValues

	s      *Session
	rs     *requestStream
	order  v22.GroupOrder
	stream chan *fetchStream

	r   *v22.FetchReader
	str ReceiveStream

	doneOnce sync.Once
	done     chan struct{}
	err      error
}

type fetchStream struct {
	str ReceiveStream
	br  *bufio.Reader
}

func (f *IncomingFetch) deliver(fs *fetchStream) {
	select {
	case f.stream <- fs:
	default:
		fs.str.CancelRead(uint64(v22.ResetCancelled)) // a second stream for one fetch
	}
}

// drainRequest waits for the responder to finish the request stream.
func (f *IncomingFetch) drainRequest() {
	for {
		if _, err := f.rs.recv(); err != nil {
			return
		}
	}
}

func (f *IncomingFetch) finish(err error) {
	f.doneOnce.Do(func() {
		f.err = err
		close(f.done)
		f.s.mu.Lock()
		if f.s.fetches[f.RequestID] == f {
			delete(f.s.fetches, f.RequestID)
		}
		f.s.mu.Unlock()
	})
}

// Next returns the next entry: an Object or an End of Range marker
// (FetchObject.Range). It returns io.EOF once the fetch is complete.
func (f *IncomingFetch) Next(ctx context.Context) (*v22.FetchObject, error) {
	if f.r == nil {
		select {
		case fs := <-f.stream:
			f.str, f.r = fs.str, v22.NewFetchReader(fs.br, f.order)
		case <-f.done:
			return nil, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.s.ctx.Done():
			return nil, f.s.Err()
		}
	}
	stop := context.AfterFunc(ctx, func() { f.str.CancelRead(uint64(v22.ResetCancelled)) })
	defer stop()
	o, err := f.r.Next()
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		var se *v22.SessionError
		if errors.As(err, &se) {
			f.s.fail(se)
		}
		if err == io.EOF {
			f.rs.finish()
		}
		f.finish(err)
		return nil, f.err
	}
	return o, nil
}

// Cancel abandons the fetch. After Next returned io.EOF it does nothing.
func (f *IncomingFetch) Cancel() {
	select {
	case <-f.done:
		if f.err == io.EOF {
			return
		}
	default:
	}
	f.finish(ErrFetchCancelled)
	f.rs.cancel(v22.ResetCancelled)
	select {
	case fs := <-f.stream:
		fs.str.CancelRead(uint64(v22.ResetCancelled))
	default:
	}
	if f.str != nil {
		f.str.CancelRead(uint64(v22.ResetCancelled))
	}
}

// handleFetchStream routes a fetch data stream to its fetch by Request ID.
func (s *Session) handleFetchStream(str ReceiveStream, br *bufio.Reader) {
	id, err := v22.ReadVarint(br)
	if err != nil {
		return
	}
	s.mu.Lock()
	f := s.fetches[id]
	s.mu.Unlock()
	if f == nil {
		str.CancelRead(uint64(v22.ResetCancelled))
		return
	}
	f.deliver(&fetchStream{str: str, br: br})
}

// FetchRequest is an incoming FETCH.
type FetchRequest struct {
	RequestID uint64
	Track     v22.FullTrackName
	Params    *v22.Params

	s  *Session
	rs *requestStream
}

// Reject answers with REQUEST_ERROR.
func (r *FetchRequest) Reject(code v22.RequestErrorCode, reason string) error {
	return r.rs.reject(code, reason)
}

// FetchAcceptOptions are the responder's answer to a FETCH.
type FetchAcceptOptions struct {
	EndOfTrack  bool
	EndLocation v22.Location // the largest Location the fetch will return
	Properties  v22.KeyValues
}

// Accept answers with FETCH_OK and returns the writer for the fetch's data
// stream.
func (r *FetchRequest) Accept(opts FetchAcceptOptions) (*FetchResponder, error) {
	info, err := v22.ParseTrackInfo(opts.Properties)
	if err != nil {
		return nil, err
	}
	order := info.GroupOrder
	prio := info.PublisherPriority
	if r.Params != nil {
		if r.Params.GroupOrder != nil {
			order = *r.Params.GroupOrder
		}
		if r.Params.SubscriberPriority != nil {
			prio = *r.Params.SubscriberPriority
		}
	}
	ok := &v22.FetchOK{EndOfTrack: opts.EndOfTrack, EndLocation: opts.EndLocation, Params: &v22.Params{}, TrackProperties: opts.Properties}
	if err := r.rs.send(ok); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(r.s.ctx)
	w := &FetchResponder{
		Track:     r.Track,
		RequestID: r.RequestID,
		Order:     order,
		s:         r.s,
		rs:        r.rs,
		ctx:       ctx,
		cancel:    cancel,
		prio:      prio,
		enc:       v22.NewFetchWriter(order),
	}
	go w.watch()
	return w, nil
}

// FetchResponder writes the Objects of an accepted fetch.
type FetchResponder struct {
	Track     v22.FullTrackName
	RequestID uint64
	Order     v22.GroupOrder // the order entries must be written in

	s      *Session
	rs     *requestStream
	ctx    context.Context
	cancel context.CancelCauseFunc
	prio   uint8
	enc    *v22.FetchWriter
	buf    []byte

	mu     sync.Mutex
	str    SendStream
	reset  bool
	closed bool
}

// watch cancels the responder when the requester resets the request.
func (w *FetchResponder) watch() {
	for {
		if _, err := w.rs.recv(); err != nil {
			if err != io.EOF {
				w.cancel(ErrSubscriberGone)
			}
			return
		}
	}
}

// Context is cancelled when the requester cancels or the session ends.
func (w *FetchResponder) Context() context.Context { return w.ctx }

func (w *FetchResponder) open() (SendStream, error) {
	w.mu.Lock()
	str, reset := w.str, w.reset
	w.mu.Unlock()
	if reset {
		return nil, ErrSubgroupReset
	}
	if str != nil {
		return str, nil
	}
	str, err := w.s.conn.OpenUniStreamSync(w.ctx)
	if err != nil {
		return nil, err
	}
	str.SetPriority(w.prio)
	w.mu.Lock()
	w.str = str
	reset = w.reset
	w.mu.Unlock()
	if reset {
		str.CancelWrite(uint64(v22.ResetCancelled))
		return nil, ErrSubgroupReset
	}
	w.buf = v22.FetchHeader{RequestID: w.RequestID}.Append(w.buf[:0])
	return str, nil
}

// WriteObject writes one entry, in Order: an Object or an End of Range
// marker.
func (w *FetchResponder) WriteObject(o *v22.FetchObject) error {
	str, err := w.open()
	if err != nil {
		return err
	}
	if w.buf, err = w.enc.Append(w.buf, o); err != nil {
		return err
	}
	_, err = str.Write(w.buf)
	w.buf = w.buf[:0]
	return err
}

// Close ends the fetch after its last entry. A fetch with no entries still
// gets a stream with just its header, so the requester sees the end.
func (w *FetchResponder) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()
	str, err := w.open()
	if err == nil {
		if len(w.buf) > 0 {
			_, err = str.Write(w.buf)
			w.buf = w.buf[:0]
		}
		if cerr := str.Close(); err == nil {
			err = cerr
		}
	}
	w.rs.finish()
	w.cancel(errors.New("moqt: fetch done"))
	return err
}

// Reset abandons the fetch's data stream. It is safe to call while
// WriteObject is blocked.
func (w *FetchResponder) Reset(code v22.StreamResetCode) {
	w.mu.Lock()
	w.reset = true
	str := w.str
	w.mu.Unlock()
	if str != nil {
		str.CancelWrite(uint64(code))
	}
	w.rs.finish()
	w.cancel(errors.New("moqt: fetch reset"))
}
