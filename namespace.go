package moqt

import (
	"context"
	"errors"
	"io"
	"sync"

	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// PublishNamespace advertises that this endpoint publishes tracks under
// prefix, and waits for the peer to accept.
func (s *Session) PublishNamespace(ctx context.Context, prefix v22.Namespace, params *v22.Params) (*PublishedNamespace, error) {
	if err := prefix.Validate(); err != nil {
		return nil, err
	}
	rs, err := s.openRequest(ctx)
	if err != nil {
		return nil, err
	}
	if params == nil {
		params = &v22.Params{}
	}
	if err := rs.send(&v22.PublishNamespace{RequestID: s.nextRequestID(), Prefix: prefix, Params: params}); err != nil {
		rs.cancel(v22.ResetInternalError)
		return nil, err
	}
	m, err := rs.recvCtx(ctx)
	if err != nil {
		return nil, err
	}
	switch m := m.(type) {
	case *v22.RequestOK:
		pn := &PublishedNamespace{Prefix: prefix, rs: rs, done: make(chan struct{})}
		go func() {
			watchCancel(rs)
			close(pn.done)
		}()
		return pn, nil
	case *v22.RequestError:
		rs.finish()
		return nil, requestError(m)
	default:
		err := unexpected(m, "PUBLISH_NAMESPACE response")
		s.fail(err)
		return nil, err
	}
}

// watchCancel blocks until the peer cancels the request: a reset of its
// direction or STOP_SENDING on ours. A FIN from the peer only means it has
// nothing more to send, which is not a cancellation (Section 6.4.2.2).
func watchCancel(rs *requestStream) {
	readErr := make(chan error, 1)
	go func() {
		for {
			if _, err := rs.recv(); err != nil {
				readErr <- err
				return
			}
		}
	}()
	select {
	case err := <-readErr:
		if err != io.EOF {
			return
		}
		<-rs.str.Context().Done()
	case <-rs.str.Context().Done():
	}
}

// PublishedNamespace is an accepted PUBLISH_NAMESPACE.
type PublishedNamespace struct {
	Prefix v22.Namespace
	rs     *requestStream
	done   chan struct{}
}

// Done is closed when the peer revokes the namespace or the session ends.
func (p *PublishedNamespace) Done() <-chan struct{} { return p.done }

// Withdraw cancels the PUBLISH_NAMESPACE (Section 4.1).
func (p *PublishedNamespace) Withdraw() { p.rs.cancel(v22.ResetCancelled) }

// PublishNamespaceRequest is an incoming PUBLISH_NAMESPACE.
type PublishNamespaceRequest struct {
	RequestID uint64
	Prefix    v22.Namespace
	Params    *v22.Params
	rs        *requestStream
}

func (r *PublishNamespaceRequest) Reject(code v22.RequestErrorCode, reason string) error {
	return r.rs.reject(code, reason)
}

// Accept answers REQUEST_OK. The returned namespace's Done closes when the
// publisher withdraws it.
func (r *PublishNamespaceRequest) Accept() (*AcceptedNamespace, error) {
	if err := r.rs.send(&v22.RequestOK{Params: &v22.Params{}}); err != nil {
		return nil, err
	}
	an := &AcceptedNamespace{Prefix: r.Prefix, rs: r.rs, done: make(chan struct{})}
	go func() {
		watchCancel(r.rs)
		close(an.done)
	}()
	return an, nil
}

// AcceptedNamespace is a namespace a peer published to this endpoint.
type AcceptedNamespace struct {
	Prefix v22.Namespace
	rs     *requestStream
	done   chan struct{}
}

// Done is closed when the publisher withdraws the namespace.
func (a *AcceptedNamespace) Done() <-chan struct{} { return a.done }

// Revoke cancels acceptance of the namespace.
func (a *AcceptedNamespace) Revoke() { a.rs.cancel(v22.ResetCancelled) }

// NamespaceEvent reports a namespace appearing (Active) or going away.
type NamespaceEvent struct {
	Suffix v22.Namespace // relative to the subscribed prefix
	Active bool
}

// SubscribeNamespace asks the peer for the namespaces under prefix and
// their changes.
func (s *Session) SubscribeNamespace(ctx context.Context, prefix v22.Namespace, params *v22.Params) (*NamespaceSubscription, error) {
	if err := prefix.Validate(); err != nil {
		return nil, err
	}
	rs, err := s.openRequest(ctx)
	if err != nil {
		return nil, err
	}
	if params == nil {
		params = &v22.Params{}
	}
	if err := rs.send(&v22.SubscribeNamespace{RequestID: s.nextRequestID(), Prefix: prefix, Params: params}); err != nil {
		rs.cancel(v22.ResetInternalError)
		return nil, err
	}
	m, err := rs.recvCtx(ctx)
	if err != nil {
		return nil, err
	}
	switch m := m.(type) {
	case *v22.RequestOK:
		ns := &NamespaceSubscription{Prefix: prefix, s: s, rs: rs, events: make(chan NamespaceEvent, 64), done: make(chan struct{})}
		go ns.read()
		return ns, nil
	case *v22.RequestError:
		rs.finish()
		return nil, requestError(m)
	default:
		err := unexpected(m, "SUBSCRIBE_NAMESPACE response")
		s.fail(err)
		return nil, err
	}
}

// NamespaceSubscription receives NAMESPACE and NAMESPACE_DONE.
type NamespaceSubscription struct {
	Prefix v22.Namespace
	s      *Session
	rs     *requestStream
	events chan NamespaceEvent
	done   chan struct{}
}

func (n *NamespaceSubscription) read() {
	active := map[string]v22.Namespace{}
	defer func() {
		// A closed or reset stream ends every namespace (Section 4.2.2).
		for _, suffix := range active {
			n.emit(NamespaceEvent{Suffix: suffix})
		}
		close(n.done)
	}()
	for {
		m, err := n.rs.recv()
		if err != nil {
			return
		}
		switch m := m.(type) {
		case *v22.NamespaceMsg:
			if _, dup := active[m.Suffix.Key()]; dup {
				continue
			}
			active[m.Suffix.Key()] = m.Suffix
			n.emit(NamespaceEvent{Suffix: m.Suffix, Active: true})
		case *v22.NamespaceDone:
			if _, ok := active[m.Suffix.Key()]; !ok {
				n.s.fail(&v22.SessionError{Code: v22.ErrProtocolViolation, Reason: "NAMESPACE_DONE before NAMESPACE"})
				return
			}
			delete(active, m.Suffix.Key())
			n.emit(NamespaceEvent{Suffix: m.Suffix})
		default:
			n.s.fail(unexpected(m, "SUBSCRIBE_NAMESPACE response stream"))
			return
		}
	}
}

func (n *NamespaceSubscription) emit(e NamespaceEvent) {
	select {
	case n.events <- e:
	case <-n.s.ctx.Done():
	}
}

// Next returns the next namespace change, or io.EOF when the subscription
// has ended.
func (n *NamespaceSubscription) Next(ctx context.Context) (NamespaceEvent, error) {
	select {
	case e := <-n.events:
		return e, nil
	case <-ctx.Done():
		return NamespaceEvent{}, ctx.Err()
	case <-n.done:
		select {
		case e := <-n.events:
			return e, nil
		default:
			return NamespaceEvent{}, io.EOF
		}
	}
}

// Cancel ends the namespace subscription.
func (n *NamespaceSubscription) Cancel() { n.rs.cancel(v22.ResetCancelled) }

// SubscribeNamespaceRequest is an incoming SUBSCRIBE_NAMESPACE.
type SubscribeNamespaceRequest struct {
	RequestID uint64
	Prefix    v22.Namespace
	Params    *v22.Params
	rs        *requestStream
}

func (r *SubscribeNamespaceRequest) Reject(code v22.RequestErrorCode, reason string) error {
	return r.rs.reject(code, reason)
}

// Accept answers REQUEST_OK; the caller then reports namespaces through
// the returned announcer.
func (r *SubscribeNamespaceRequest) Accept() (*NamespaceAnnouncer, error) {
	if err := r.rs.send(&v22.RequestOK{Params: &v22.Params{}}); err != nil {
		return nil, err
	}
	a := &NamespaceAnnouncer{Prefix: r.Prefix, rs: r.rs, active: map[string]bool{}, done: make(chan struct{})}
	go func() {
		watchCancel(r.rs)
		close(a.done)
	}()
	return a, nil
}

// NamespaceAnnouncer sends NAMESPACE / NAMESPACE_DONE to a namespace
// subscriber.
type NamespaceAnnouncer struct {
	Prefix v22.Namespace
	rs     *requestStream
	done   chan struct{}

	mu     sync.Mutex
	active map[string]bool
}

// Done is closed when the subscriber cancels.
func (a *NamespaceAnnouncer) Done() <-chan struct{} { return a.done }

// Announce reports a namespace, given as the suffix after the prefix.
func (a *NamespaceAnnouncer) Announce(suffix v22.Namespace) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active[suffix.Key()] {
		return nil
	}
	if err := a.rs.send(&v22.NamespaceMsg{Suffix: suffix}); err != nil {
		return err
	}
	a.active[suffix.Key()] = true
	return nil
}

// Withdraw reports that a previously announced namespace has gone.
func (a *NamespaceAnnouncer) Withdraw(suffix v22.Namespace) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.active[suffix.Key()] {
		return errors.New("moqt: namespace was not announced")
	}
	delete(a.active, suffix.Key())
	return a.rs.send(&v22.NamespaceDone{Suffix: suffix})
}
