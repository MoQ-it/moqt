package relay

import (
	"context"
	"errors"
	"io"

	"github.com/MoQ-it/moqt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// FetchSource yields the entries of one FETCH in the requested group order.
type FetchSource interface {
	// Options is the FETCH_OK answer.
	Options() moqt.FetchAcceptOptions
	// Next returns the next Object or End of Range marker, or io.EOF.
	Next(ctx context.Context) (*v22.FetchObject, error)
	Close()
}

// Archive serves FETCH from history the relay application stores. Fetch
// reports ok false when the track is not held here.
type Archive interface {
	Fetch(ctx context.Context, p *Peer, track v22.FullTrackName, params *v22.Params) (src FetchSource, ok bool, err error)
}

// FetchAuthorizer is implemented by an Authorizer that decides FETCH
// separately; otherwise FETCH is authorized like SUBSCRIBE.
type FetchAuthorizer interface {
	AuthorizeFetch(p *Peer, track v22.FullTrackName, params *v22.Params) error
}

// FetchResolver is implemented by an UpstreamResolver that can forward a
// FETCH the Archive does not hold to another relay. It returns nil, nil
// when no relay holds it.
type FetchResolver interface {
	ResolveFetch(ctx context.Context, track v22.FullTrackName, params *v22.Params) (*moqt.Session, error)
}

// HandleFetch answers a FETCH from the Archive, or forwards it through the
// FetchResolver. A FETCH is never forwarded to a publisher, and the
// in-memory Group cache does not serve it.
func (p *Peer) HandleFetch(req *moqt.FetchRequest) {
	if !p.waitAttached() {
		req.Reject(v22.ReqErrInternal, "session not ready")
		return
	}
	r := p.r
	if a := r.cfg.Authorizer; a != nil {
		var err error
		if fa, ok := a.(FetchAuthorizer); ok {
			err = fa.AuthorizeFetch(p, req.Track, req.Params)
		} else {
			err = a.AuthorizeSubscribe(p, req.Track, req.Params)
		}
		if err != nil {
			req.Reject(requestErr(err))
			return
		}
	}
	if r.cfg.FetchLimit != nil {
		if limit := r.cfg.FetchLimit(p); limit > 0 {
			defer p.fetches.Add(-1)
			if int(p.fetches.Add(1)) > limit {
				req.Reject(v22.ReqErrExcessiveLoad, "too many fetches")
				return
			}
		}
	}
	ctx, cancel := context.WithTimeout(p.sess.Context(), r.cfg.UpstreamTimeout)
	src, err := r.fetchSource(ctx, p, req.Track, req.Params)
	cancel()
	if err != nil {
		code, reason := v22.ReqErrInternal, err.Error()
		var re *moqt.RequestError
		if errors.As(err, &re) {
			code, reason = re.Code, re.Reason
		}
		req.Reject(code, reason)
		return
	}
	if src == nil {
		req.Reject(v22.ReqErrDoesNotExist, "track not archived")
		return
	}
	defer src.Close()
	w, err := req.Accept(src.Options())
	if err != nil {
		return
	}
	for {
		o, err := src.Next(w.Context())
		if err == io.EOF {
			w.Close()
			return
		}
		if err != nil {
			r.log.Debug("fetch ended early", "track", req.Track, "err", err)
			w.Reset(v22.ResetCancelled)
			return
		}
		if err := w.WriteObject(o); err != nil {
			w.Reset(v22.ResetCancelled)
			return
		}
	}
}

func (r *Relay) fetchSource(ctx context.Context, p *Peer, track v22.FullTrackName, params *v22.Params) (FetchSource, error) {
	if r.cfg.Archive != nil {
		src, ok, err := r.cfg.Archive.Fetch(ctx, p, track, params)
		if err != nil || ok {
			return src, err
		}
	}
	fr, ok := r.cfg.Upstream.(FetchResolver)
	if !ok {
		return nil, nil
	}
	sess, err := fr.ResolveFetch(ctx, track, params)
	if err != nil || sess == nil {
		return nil, err
	}
	up := &v22.Params{}
	if params != nil {
		cp := *params
		cp.AuthorizationTokens = nil // the upstream session carries its own authority
		up = &cp
	}
	f, err := sess.Fetch(ctx, track, up)
	if err != nil {
		return nil, err
	}
	return upstreamFetch{f}, nil
}

type upstreamFetch struct{ f *moqt.IncomingFetch }

func (u upstreamFetch) Options() moqt.FetchAcceptOptions {
	return moqt.FetchAcceptOptions{EndOfTrack: u.f.EndOfTrack, EndLocation: u.f.EndLocation, Properties: u.f.Properties}
}

func (u upstreamFetch) Next(ctx context.Context) (*v22.FetchObject, error) { return u.f.Next(ctx) }

func (u upstreamFetch) Close() { u.f.Cancel() }
