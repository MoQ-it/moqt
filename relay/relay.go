// Package relay is a generic MOQT relay: it accepts namespaces from
// publishers, serves subscriptions with a single upstream subscription per
// track, and fans Objects out to every subscriber. Applications plug in
// authorization, upstream discovery (e.g. other relay nodes) and Object
// observation through Config.
package relay

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MoQ-it/moqt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// Authorizer decides whether a peer may make a request. Returning a
// *moqt.RequestError selects the REQUEST_ERROR code; any other error is
// UNAUTHORIZED. A nil Authorizer allows everything.
type Authorizer interface {
	AuthorizePublishNamespace(p *Peer, prefix v22.Namespace, params *v22.Params) error
	AuthorizeSubscribe(p *Peer, track v22.FullTrackName, params *v22.Params) error
	AuthorizeSubscribeNamespace(p *Peer, prefix v22.Namespace, params *v22.Params) error
}

// UpstreamResolver finds a session to subscribe to a track from when no
// local peer has published a matching namespace, e.g. another relay node.
// It returns nil, nil when the track is unknown.
type UpstreamResolver interface {
	ResolveUpstream(ctx context.Context, track v22.FullTrackName) (*moqt.Session, error)
}

// Config configures a Relay.
type Config struct {
	Authorizer Authorizer
	Upstream   UpstreamResolver
	// ObjectHook, if set, sees every Object received from upstream before it
	// is forwarded (e.g. to read an audio level property). It must not
	// block or modify the Object.
	ObjectHook func(track v22.FullTrackName, group uint64, o *v22.Object)
	// Archive, if set, serves FETCH from stored history.
	Archive Archive
	// FetchLimit, if set, caps the FETCHes a peer may have open at once;
	// 0 means no cap. More are rejected with EXCESSIVE_LOAD.
	FetchLimit func(p *Peer) int
	// NamespaceHook, if set, is told when a peer's PUBLISH_NAMESPACE is
	// accepted (active) and when it ends.
	NamespaceHook func(p *Peer, prefix v22.Namespace, active bool)
	// CachedGroups is how many of the latest Groups are kept for
	// subscribers that join mid-stream (default 2).
	CachedGroups int
	// Linger keeps an upstream subscription this long after its last
	// subscriber leaves, so quick re-subscribes reuse it (default 2s).
	Linger time.Duration
	// UpstreamTimeout bounds establishing an upstream subscription (default 5s).
	UpstreamTimeout time.Duration
	// DeliveryTimeout is how far a subscriber may fall behind the live edge:
	// a subgroup still being sent this long after a newer Group started is
	// reset, so a congested subscriber skips ahead instead of queueing stale
	// media. A subscriber's SUBGROUP_DELIVERY_TIMEOUT overrides it.
	// Default 1s; negative disables.
	DeliveryTimeout time.Duration
	Logger          *slog.Logger
}

// Relay is a MOQT relay.
type Relay struct {
	cfg Config
	log *slog.Logger

	mu         sync.Mutex
	tracks     map[string]*track // by FullTrackName.Key()
	published  []*publishedNamespace
	nsWatchers []*namespaceWatcher
}

func New(cfg Config) *Relay {
	if cfg.CachedGroups <= 0 {
		cfg.CachedGroups = 2
	}
	if cfg.Linger == 0 {
		cfg.Linger = 2 * time.Second
	}
	if cfg.UpstreamTimeout == 0 {
		cfg.UpstreamTimeout = 5 * time.Second
	}
	if cfg.DeliveryTimeout == 0 {
		cfg.DeliveryTimeout = time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Relay{cfg: cfg, log: cfg.Logger, tracks: map[string]*track{}}
}

// Peer is one session connected to the relay. Use it as the session's
// moqt.Handler and Attach the session once NewSession returns.
type Peer struct {
	// Info is application data about the peer, e.g. its authenticated
	// identity, for the Authorizer.
	Info any

	r        *Relay
	attached chan struct{}
	sess     *moqt.Session
	fetches  atomic.Int32
}

// NewPeer returns a handler for a new session.
func (r *Relay) NewPeer(info any) *Peer {
	return &Peer{Info: info, r: r, attached: make(chan struct{})}
}

// Attach binds the session; requests wait for it.
func (p *Peer) Attach(s *moqt.Session) {
	p.sess = s
	close(p.attached)
}

// Session returns the attached session.
func (p *Peer) Session() *moqt.Session { return p.sess }

func (p *Peer) waitAttached() bool {
	select {
	case <-p.attached:
		return true
	case <-time.After(10 * time.Second):
		return false
	}
}

func requestErr(err error) (v22.RequestErrorCode, string) {
	var re *moqt.RequestError
	if errors.As(err, &re) {
		return re.Code, re.Reason
	}
	return v22.ReqErrUnauthorized, err.Error()
}

// publishedNamespace is a PUBLISH_NAMESPACE a peer made to the relay.
type publishedNamespace struct {
	prefix v22.Namespace
	peer   *Peer
}

// namespaceWatcher is a SUBSCRIBE_NAMESPACE a peer made to the relay.
type namespaceWatcher struct {
	prefix v22.Namespace
	peer   *Peer
	ann    *moqt.NamespaceAnnouncer
}

func (w *namespaceWatcher) announce(ns v22.Namespace, active bool) {
	if !ns.HasPrefix(w.prefix) {
		return
	}
	suffix := ns[len(w.prefix):]
	if active {
		w.ann.Announce(suffix)
	} else {
		w.ann.Withdraw(suffix)
	}
}

// HandlePublishNamespace accepts a publisher's namespace and tells
// namespace subscribers about it.
func (p *Peer) HandlePublishNamespace(req *moqt.PublishNamespaceRequest) {
	if !p.waitAttached() {
		req.Reject(v22.ReqErrInternal, "session not ready")
		return
	}
	r := p.r
	if r.cfg.Authorizer != nil {
		if err := r.cfg.Authorizer.AuthorizePublishNamespace(p, req.Prefix, req.Params); err != nil {
			req.Reject(requestErr(err))
			return
		}
	}
	acc, err := req.Accept()
	if err != nil {
		return
	}
	pn := &publishedNamespace{prefix: req.Prefix, peer: p}
	r.mu.Lock()
	r.published = append(r.published, pn)
	watchers := slices.Clone(r.nsWatchers)
	r.mu.Unlock()
	for _, w := range watchers {
		if w.peer != p {
			w.announce(pn.prefix, true)
		}
	}
	r.log.Debug("namespace published", "prefix", req.Prefix)
	if r.cfg.NamespaceHook != nil {
		r.cfg.NamespaceHook(p, req.Prefix, true)
	}

	select {
	case <-acc.Done():
	case <-p.sess.Context().Done():
	}
	if r.cfg.NamespaceHook != nil {
		r.cfg.NamespaceHook(p, pn.prefix, false)
	}
	r.mu.Lock()
	r.published = slices.DeleteFunc(r.published, func(x *publishedNamespace) bool { return x == pn })
	stillPublished := r.publisherLocked(pn.prefix) != nil
	watchers = slices.Clone(r.nsWatchers)
	r.mu.Unlock()
	if !stillPublished {
		for _, w := range watchers {
			if w.peer != p {
				w.announce(pn.prefix, false)
			}
		}
	}
}

// publisherLocked returns the peer that published the longest namespace
// prefix of ns, if any. Among equal prefixes the most recent publication
// wins, so a reconnecting publisher takes over from its old session.
func (r *Relay) publisherLocked(ns v22.Namespace) *Peer {
	var best *publishedNamespace
	for _, pn := range r.published {
		if ns.HasPrefix(pn.prefix) && (best == nil || len(pn.prefix) >= len(best.prefix)) {
			best = pn
		}
	}
	if best == nil {
		return nil
	}
	return best.peer
}

// HandleSubscribeNamespace reports published namespaces under a prefix.
func (p *Peer) HandleSubscribeNamespace(req *moqt.SubscribeNamespaceRequest) {
	if !p.waitAttached() {
		req.Reject(v22.ReqErrInternal, "session not ready")
		return
	}
	r := p.r
	if r.cfg.Authorizer != nil {
		if err := r.cfg.Authorizer.AuthorizeSubscribeNamespace(p, req.Prefix, req.Params); err != nil {
			req.Reject(requestErr(err))
			return
		}
	}
	ann, err := req.Accept()
	if err != nil {
		return
	}
	w := &namespaceWatcher{prefix: req.Prefix, peer: p, ann: ann}
	r.mu.Lock()
	r.nsWatchers = append(r.nsWatchers, w)
	var existing []v22.Namespace
	for _, pn := range r.published {
		if pn.peer != p {
			existing = append(existing, pn.prefix)
		}
	}
	r.mu.Unlock()
	for _, ns := range existing {
		w.announce(ns, true)
	}
	select {
	case <-ann.Done():
	case <-p.sess.Context().Done():
	}
	r.mu.Lock()
	r.nsWatchers = slices.DeleteFunc(r.nsWatchers, func(x *namespaceWatcher) bool { return x == w })
	r.mu.Unlock()
}

// HandleSubscribe serves a subscription from the relay's track state,
// subscribing upstream if this is the track's first subscriber.
func (p *Peer) HandleSubscribe(req *moqt.SubscribeRequest) {
	if !p.waitAttached() {
		req.Reject(v22.ReqErrInternal, "session not ready")
		return
	}
	r := p.r
	if r.cfg.Authorizer != nil {
		if err := r.cfg.Authorizer.AuthorizeSubscribe(p, req.Track, req.Params); err != nil {
			req.Reject(requestErr(err))
			return
		}
	}
	// A track can close (idle linger, upstream end) between lookup and
	// accept; then retry once with a fresh upstream subscription.
	for range 2 {
		t, err := r.track(req.Track, req.Params, nil)
		if err != nil {
			code, reason := v22.ReqErrInternal, err.Error()
			var re *moqt.RequestError
			if errors.As(err, &re) {
				code, reason = re.Code, re.Reason
			}
			req.Reject(code, reason)
			return
		}
		if t.addSubscriber(req) {
			return
		}
	}
	req.Reject(v22.ReqErrInternal, "track closed")
}

// track returns the relay's state for a track, establishing the upstream
// subscription on first use. attach, if set, runs on the track under its
// lock before any Object can arrive, unless the track has closed.
func (r *Relay) track(name v22.FullTrackName, params *v22.Params, attach func(*track)) (*track, error) {
	key := name.Key()
	r.mu.Lock()
	t := r.tracks[key]
	if t == nil {
		t = newTrack(r, name)
		if attach != nil {
			attach(t)
		}
		r.tracks[key] = t
		r.mu.Unlock()
		go t.establish(params)
	} else {
		r.mu.Unlock()
		if attach != nil {
			t.mu.Lock()
			if !t.closed {
				attach(t)
			}
			t.mu.Unlock()
		}
		if params != nil && params.NewGroupRequest != nil {
			defer t.newGroupRequest(*params.NewGroupRequest)
		}
	}
	select {
	case <-t.ready:
	case <-time.After(r.cfg.UpstreamTimeout + time.Second):
		return nil, &moqt.RequestError{Code: v22.ReqErrTimeout, Reason: "upstream not ready"}
	}
	if t.err != nil {
		return nil, t.err
	}
	return t, nil
}

// resolveUpstream picks the session a track is subscribed from.
func (r *Relay) resolveUpstream(ctx context.Context, name v22.FullTrackName) (*moqt.Session, error) {
	r.mu.Lock()
	pub := r.publisherLocked(name.Namespace)
	r.mu.Unlock()
	if pub != nil {
		return pub.sess, nil
	}
	if r.cfg.Upstream != nil {
		return r.cfg.Upstream.ResolveUpstream(ctx, name)
	}
	return nil, nil
}

func (r *Relay) removeTrack(t *track) {
	r.mu.Lock()
	if r.tracks[t.name.Key()] == t {
		delete(r.tracks, t.name.Key())
	}
	r.mu.Unlock()
}

// TrackCount reports how many tracks have live upstream subscriptions.
func (r *Relay) TrackCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tracks)
}
