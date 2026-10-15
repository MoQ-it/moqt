package relay_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/MoQ-it/moqt"
	"github.com/MoQ-it/moqt/relay"
	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// sliceArchive holds fixed entries for one track.
type sliceArchive struct {
	track   v22.FullTrackName
	entries []*v22.FetchObject
}

func (a *sliceArchive) Fetch(_ context.Context, _ *relay.Peer, track v22.FullTrackName, _ *v22.Params) (relay.FetchSource, bool, error) {
	if track.Key() != a.track.Key() {
		return nil, false, nil
	}
	return &sliceSource{entries: a.entries}, true, nil
}

type sliceSource struct{ entries []*v22.FetchObject }

func (s *sliceSource) Options() moqt.FetchAcceptOptions {
	last := s.entries[len(s.entries)-1]
	return moqt.FetchAcceptOptions{EndLocation: v22.Location{Group: last.Group, Object: last.Object}}
}

func (s *sliceSource) Next(context.Context) (*v22.FetchObject, error) {
	if len(s.entries) == 0 {
		return nil, io.EOF
	}
	o := s.entries[0]
	s.entries = s.entries[1:]
	return o, nil
}

func (s *sliceSource) Close() {}

func archived() *sliceArchive {
	a := &sliceArchive{track: cam}
	for g := uint64(10); g < 13; g++ {
		for o := uint64(0); o < 3; o++ {
			a.entries = append(a.entries, &v22.FetchObject{Group: g, Object: o, Priority: 1, Payload: []byte(fmt.Sprintf("%d/%d", g, o))})
		}
	}
	return a
}

func fetchAll(t *testing.T, ctx context.Context, s *moqt.Session, track v22.FullTrackName) ([]string, error) {
	t.Helper()
	f, err := s.Fetch(ctx, track, &v22.Params{LocationFilter: &v22.LocationFilter{Type: v22.FilterAbsoluteRange, StartGroup: 10, EndGroupDelta: 2}})
	if err != nil {
		return nil, err
	}
	var got []string
	for {
		o, err := f.Next(ctx)
		if err == io.EOF {
			return got, nil
		}
		if err != nil {
			return got, err
		}
		got = append(got, string(o.Payload))
	}
}

const wantArchived = "[10/0 10/1 10/2 11/0 11/1 11/2 12/0 12/1 12/2]"

func TestFetchFromArchive(t *testing.T) {
	h := newHarness(t, relay.Config{Archive: archived()})
	ctx := ctxT(t)
	got, err := fetchAll(t, ctx, h.connect(nil), cam)
	if err != nil || fmt.Sprint(got) != wantArchived {
		t.Fatalf("got %v, %v", got, err)
	}
	// A published track the archive does not hold is not fetched from its
	// publisher.
	pub := newPublisher(nil)
	if _, err := h.connect(pub).PublishNamespace(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}
	_, err = fetchAll(t, ctx, h.connect(nil), v22.FullTrackName{Namespace: alice, Name: "mic"})
	var re *moqt.RequestError
	if !errors.As(err, &re) || re.Code != v22.ReqErrDoesNotExist {
		t.Fatalf("got %v; want DOES_NOT_EXIST", err)
	}
	if n := pub.subscribes.Load(); n != 0 {
		t.Errorf("publisher got %d requests", n)
	}
}

// fetchUpstream forwards FETCH to a fixed session.
type fetchUpstream struct {
	sess   func() *moqt.Session
	params chan *v22.Params
}

func (u *fetchUpstream) ResolveUpstream(context.Context, v22.FullTrackName) (*moqt.Session, error) {
	return nil, nil
}

func (u *fetchUpstream) ResolveFetch(_ context.Context, _ v22.FullTrackName, p *v22.Params) (*moqt.Session, error) {
	u.params <- p
	return u.sess(), nil
}

func TestFetchForwardedUpstream(t *testing.T) {
	origin := newHarness(t, relay.Config{Archive: archived()})
	var once sync.Once
	var up *moqt.Session
	u := &fetchUpstream{params: make(chan *v22.Params, 1), sess: func() *moqt.Session {
		once.Do(func() { up = origin.connect(nil) })
		return up
	}}
	edge := newHarness(t, relay.Config{Upstream: u})
	ctx := ctxT(t)
	got, err := fetchAll(t, ctx, edge.connect(nil), cam)
	if err != nil || fmt.Sprint(got) != wantArchived {
		t.Fatalf("got %v, %v", got, err)
	}
	if p := <-u.params; p.LocationFilter == nil || p.LocationFilter.StartGroup != 10 {
		t.Errorf("resolver params %+v", p)
	}
	// Errors from the upstream relay are passed on.
	_, err = fetchAll(t, ctx, edge.connect(nil), v22.FullTrackName{Namespace: alice, Name: "mic"})
	var re *moqt.RequestError
	if !errors.As(err, &re) || re.Code != v22.ReqErrDoesNotExist {
		t.Fatalf("got %v; want DOES_NOT_EXIST", err)
	}
}

type denyFetch struct{ denyScreen }

func (denyFetch) AuthorizeFetch(*relay.Peer, v22.FullTrackName, *v22.Params) error {
	return &moqt.RequestError{Code: v22.ReqErrUnauthorized, Reason: "viewers only"}
}

func TestFetchAuthorization(t *testing.T) {
	ctx := ctxT(t)
	h := newHarness(t, relay.Config{Archive: archived(), Authorizer: denyFetch{}})
	_, err := fetchAll(t, ctx, h.connect(nil), cam)
	var re *moqt.RequestError
	if !errors.As(err, &re) || re.Reason != "viewers only" {
		t.Fatalf("got %v; want the FetchAuthorizer's error", err)
	}
	// Without AuthorizeFetch, FETCH is authorized like SUBSCRIBE.
	a := archived()
	a.track = v22.FullTrackName{Namespace: alice, Name: "screen-h"}
	h = newHarness(t, relay.Config{Archive: a, Authorizer: denyScreen{}})
	if _, err := fetchAll(t, ctx, h.connect(nil), a.track); !errors.As(err, &re) || re.Code != v22.ReqErrUnauthorized {
		t.Fatalf("got %v; want UNAUTHORIZED", err)
	}
}

// blockingArchive holds every fetch open until release closes.
type blockingArchive struct{ release chan struct{} }

func (a blockingArchive) Fetch(context.Context, *relay.Peer, v22.FullTrackName, *v22.Params) (relay.FetchSource, bool, error) {
	return blockingSource(a), true, nil
}

type blockingSource blockingArchive

func (blockingSource) Options() moqt.FetchAcceptOptions { return moqt.FetchAcceptOptions{} }
func (b blockingSource) Next(ctx context.Context) (*v22.FetchObject, error) {
	select {
	case <-b.release:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (blockingSource) Close() {}

func TestFetchLimit(t *testing.T) {
	a := blockingArchive{release: make(chan struct{})}
	h := newHarness(t, relay.Config{Archive: a, FetchLimit: func(*relay.Peer) int { return 2 }})
	ctx := ctxT(t)
	s := h.connect(nil)
	for range 2 {
		if _, err := s.Fetch(ctx, cam, nil); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.Fetch(ctx, cam, nil)
	var re *moqt.RequestError
	if !errors.As(err, &re) || re.Code != v22.ReqErrExcessiveLoad {
		t.Fatalf("third fetch: %v; want EXCESSIVE_LOAD", err)
	}
	// Another peer has its own allowance.
	if _, err := h.connect(nil).Fetch(ctx, cam, nil); err != nil {
		t.Fatal(err)
	}
	close(a.release)
	time.Sleep(100 * time.Millisecond)
	if _, err := s.Fetch(ctx, cam, nil); err != nil {
		t.Fatalf("after the others finished: %v", err)
	}
}

type recorded struct {
	mu      sync.Mutex
	objects []string
	ended   chan struct{}
}

func (r *recorded) RecordObject(group, subgroupID uint64, priority uint8, o *v22.Object) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.objects = append(r.objects, fmt.Sprintf("%s@%d/%d", o.Payload, subgroupID, priority))
}

func (r *recorded) RecordEnd() { close(r.ended) }

func (r *recorded) wait(t *testing.T, ctx context.Context, n int) []string {
	t.Helper()
	for {
		r.mu.Lock()
		got := append([]string(nil), r.objects...)
		r.mu.Unlock()
		if len(got) >= n {
			return got
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("recorded %v", got)
		}
	}
}

func TestRecord(t *testing.T) {
	h := newHarness(t, relay.Config{Linger: 50 * time.Millisecond})
	ctx := ctxT(t)
	pub := newPublisher(v22.KeyValues{{Type: v22.PropDefaultPublisherPriority, Int: 9}})
	if _, err := h.connect(pub).PublishNamespace(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}
	rec := &recorded{ended: make(chan struct{})}
	props, stop, err := h.r.Record(cam, rec)
	if err != nil {
		t.Fatal(err)
	}
	if kv, ok := props.Lookup(v22.PropDefaultPublisherPriority); !ok || kv.Int != 9 {
		t.Errorf("props %v", props)
	}
	w := <-pub.writers
	if p := pub.lastParams.Load(); p.NewGroupRequest == nil {
		t.Error("recording should ask for a new group")
	}
	writeGroup(t, w, 3, 2)
	if got := rec.wait(t, ctx, 2); fmt.Sprint(got) != "[3/0@0/9 3/1@0/9]" {
		t.Errorf("recorded %v", got)
	}

	// The recording keeps the upstream subscription with no subscribers.
	time.Sleep(200 * time.Millisecond)
	if n := h.r.TrackCount(); n != 1 {
		t.Fatalf("relay tracks %d tracks; want 1", n)
	}
	stop()
	select {
	case <-w.Context().Done():
	case <-ctx.Done():
		t.Fatal("upstream not released after stop")
	}

	// The publisher ending the track ends the recording.
	rec = &recorded{ended: make(chan struct{})}
	if _, _, err := h.r.Record(cam, rec); err != nil {
		t.Fatal(err)
	}
	w = <-pub.writers
	w.Close(v22.DoneTrackEnded, "bye")
	select {
	case <-rec.ended:
	case <-ctx.Done():
		t.Fatal("RecordEnd not called")
	}

	// Recording a track nobody publishes fails.
	if _, _, err := h.r.Record(v22.FullTrackName{Namespace: v22.Namespace{"nobody"}, Name: "x"}, rec); err == nil {
		t.Error("recording an unpublished track succeeded")
	}
}
