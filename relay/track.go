package relay

import (
	"context"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/MoQ-it/moqt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// track is the relay's state for one Full Track Name: the upstream
// subscription, the cache of recent Groups and the downstream subscribers.
type track struct {
	r    *Relay
	name v22.FullTrackName

	ready chan struct{} // closed once up is established or err is set
	err   error
	up    *moqt.Subscription
	props v22.KeyValues
	info  v22.TrackInfo

	mu             sync.Mutex
	groups         []*group // ascending by ID, at most Config.CachedGroups
	largest        *v22.Location
	subs           map[*downstream]struct{}
	recs           map[*recording]struct{}
	pending        int // subscribers being accepted
	linger         *time.Timer
	closed         bool
	ngrOutstanding *uint64 // NEW_GROUP_REQUEST sent upstream, until Largest Group grows

	// The live edge: the newest Group seen, when it started, and a channel
	// closed (and replaced) whenever a newer Group starts.
	liveGroup   uint64
	hasLive     bool
	liveAt      time.Time
	liveChanged chan struct{}
}

func newTrack(r *Relay, name v22.FullTrackName) *track {
	return &track{r: r, name: name, ready: make(chan struct{}), subs: map[*downstream]struct{}{}, recs: map[*recording]struct{}{}, liveChanged: make(chan struct{})}
}

// establish subscribes upstream. The relay asks for the current Group
// (relative start 1) so that it can serve joiners from a keyframe.
func (t *track) establish(first *v22.Params) {
	ctx, cancel := context.WithTimeout(context.Background(), t.r.cfg.UpstreamTimeout)
	defer cancel()
	sess, err := t.r.resolveUpstream(ctx, t.name)
	if err == nil && sess == nil {
		err = &moqt.RequestError{Code: v22.ReqErrDoesNotExist, Reason: "no publisher for track"}
	}
	if err != nil {
		t.fail(err)
		return
	}
	params := &v22.Params{LocationFilter: &v22.LocationFilter{Type: v22.FilterRelativeStart, StartGroup: 1}}
	if first != nil && first.NewGroupRequest != nil {
		params.NewGroupRequest = first.NewGroupRequest
	}
	up, err := sess.Subscribe(ctx, t.name, params)
	if err != nil {
		t.fail(err)
		return
	}
	t.up, t.props, t.info = up, up.Properties, up.Info
	t.largest = up.LargestObject
	close(t.ready)
	t.r.log.Debug("upstream subscribed", "track", t.name)
	go t.pumpSubgroups()
	go t.pumpDatagrams()
}

func (t *track) fail(err error) {
	t.err = err
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	close(t.ready)
	t.r.removeTrack(t)
}

func (t *track) pumpSubgroups() {
	for {
		g, err := t.up.AcceptSubgroup(context.Background())
		if err != nil {
			code, reason := v22.DoneInternalError, "upstream ended"
			if res, _ := t.up.Result(); res != nil {
				code, reason = res.StatusCode, res.Reason
			}
			t.end(code, reason)
			return
		}
		sg := newSubgroup(g.Header.Group, g.Header)
		t.addSubgroup(sg)
		go t.pumpObjects(g, sg)
	}
}

func (t *track) pumpObjects(g *moqt.IncomingSubgroup, sg *subgroup) {
	for {
		o, err := g.Next()
		if err == io.EOF {
			sg.end(sgFinished)
			return
		}
		if err != nil {
			sg.end(sgReset)
			return
		}
		if t.r.cfg.ObjectHook != nil {
			t.r.cfg.ObjectHook(t.name, sg.group, o)
		}
		t.observe(sg.group, o.ID)
		sg.append(o)
		t.record(sg, o)
	}
}

func (t *track) pumpDatagrams() {
	for {
		d, err := t.up.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		t.observe(d.Group, d.Object)
		t.mu.Lock()
		subs := make([]*downstream, 0, len(t.subs))
		for s := range t.subs {
			subs = append(subs, s)
		}
		t.mu.Unlock()
		for _, s := range subs {
			if s.wants(d.Group) {
				cp := *d
				s.w.WriteDatagram(&cp)
			}
		}
	}
}

// observe tracks the Largest Object; a new Largest Group settles any
// outstanding NEW_GROUP_REQUEST (Section 9.20.19).
func (t *track) observe(group, object uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	loc := v22.Location{Group: group, Object: object}
	if t.largest == nil || loc.Compare(*t.largest) > 0 {
		if t.largest == nil || group > t.largest.Group {
			t.ngrOutstanding = nil
		}
		t.largest = &loc
	}
}

// addSubgroup caches a new upstream subgroup and starts forwarding it.
func (t *track) addSubgroup(sg *subgroup) {
	t.mu.Lock()
	var grp *group
	for _, g := range t.groups {
		if g.id == sg.group {
			grp = g
		}
	}
	if grp == nil {
		grp = &group{id: sg.group}
		t.groups = append(t.groups, grp)
		sort.Slice(t.groups, func(i, j int) bool { return t.groups[i].id < t.groups[j].id })
		if n := len(t.groups) - t.r.cfg.CachedGroups; n > 0 {
			t.groups = t.groups[n:]
		}
	}
	grp.subgroups = append(grp.subgroups, sg)
	if !t.hasLive || sg.group > t.liveGroup {
		t.hasLive, t.liveGroup, t.liveAt = true, sg.group, time.Now()
		close(t.liveChanged)
		t.liveChanged = make(chan struct{})
	}
	var ended []*downstream
	for s := range t.subs {
		switch {
		case s.endGroup != nil && sg.group > *s.endGroup:
			ended = append(ended, s)
		case s.wants(sg.group):
			s.startForward(sg, s.firstObject(sg.group))
		}
	}
	for _, s := range ended {
		delete(t.subs, s)
	}
	t.mu.Unlock()
	for _, s := range ended {
		s.finish(v22.DoneTrackEnded, "end of subscription range")
	}
}

// addSubscriber serves one downstream subscription. It reports false if
// the track closed before the subscriber could be added.
func (t *track) addSubscriber(req *moqt.SubscribeRequest) bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return false
	}
	t.pending++
	if t.linger != nil {
		t.linger.Stop()
		t.linger = nil
	}
	var largest *v22.Location
	if t.largest != nil {
		l := *t.largest
		largest = &l
	}
	t.mu.Unlock()

	s := &downstream{t: t, timeout: t.r.cfg.DeliveryTimeout}
	if p := req.Params; p != nil && p.SubgroupDeliveryTimeout != nil && *p.SubgroupDeliveryTimeout > 0 {
		s.timeout = time.Duration(*p.SubgroupDeliveryTimeout) * time.Millisecond
	}
	s.setFilter(req.Params, largest)
	w, err := req.Accept(moqt.AcceptOptions{Properties: t.props, LargestObject: largest})

	t.mu.Lock()
	t.pending--
	if err != nil || t.closed {
		t.mu.Unlock()
		if err == nil {
			// Already answered with SUBSCRIBE_OK, so it cannot be retried
			// here; the subscriber sees GOING_AWAY and resubscribes.
			w.Close(v22.DoneGoingAway, "track closed")
		}
		t.maybeLinger()
		return true
	}
	s.w = w
	t.subs[s] = struct{}{}
	if !s.liveOnly {
		for _, g := range t.groups {
			if s.wants(g.id) {
				for _, sg := range g.subgroups {
					s.startForward(sg, s.firstObject(g.id))
				}
			}
		}
	}
	t.mu.Unlock()
	go s.watch()
	return true
}

func (t *track) removeSubscriber(s *downstream) {
	t.mu.Lock()
	delete(t.subs, s)
	t.mu.Unlock()
	t.maybeLinger()
}

// maybeLinger schedules the upstream subscription's end once nobody uses it.
func (t *track) maybeLinger() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || len(t.subs) > 0 || len(t.recs) > 0 || t.pending > 0 || t.linger != nil {
		return
	}
	t.linger = time.AfterFunc(t.r.cfg.Linger, t.idleClose)
}

func (t *track) idleClose() {
	t.r.mu.Lock()
	t.mu.Lock()
	if len(t.subs) > 0 || len(t.recs) > 0 || t.pending > 0 || t.closed {
		t.mu.Unlock()
		t.r.mu.Unlock()
		return
	}
	t.closed = true
	if t.r.tracks[t.name.Key()] == t {
		delete(t.r.tracks, t.name.Key())
	}
	t.mu.Unlock()
	t.r.mu.Unlock()
	t.r.log.Debug("upstream released", "track", t.name)
	t.up.Unsubscribe()
}

// end closes every downstream subscription after the upstream one ended.
func (t *track) end(code v22.PublishDoneCode, reason string) {
	t.mu.Lock()
	t.closed = true
	subs, recs := t.subs, t.recs
	t.subs, t.recs = map[*downstream]struct{}{}, map[*recording]struct{}{}
	t.mu.Unlock()
	t.r.removeTrack(t)
	for s := range subs {
		s.finish(code, reason)
	}
	for rec := range recs {
		rec.end()
	}
}

// newGroupRequest handles a downstream NEW_GROUP_REQUEST on an established
// track (Section 9.20.19, Relay Handling).
func (t *track) newGroupRequest(v uint64) {
	if !t.info.DynamicGroups {
		return
	}
	t.mu.Lock()
	if v != 0 && t.largest != nil && v <= t.largest.Group {
		t.mu.Unlock()
		return
	}
	if t.ngrOutstanding != nil && *t.ngrOutstanding >= v {
		t.mu.Unlock()
		return
	}
	t.ngrOutstanding = &v
	t.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), t.r.cfg.UpstreamTimeout)
		defer cancel()
		if err := t.up.Update(ctx, &v22.Params{NewGroupRequest: &v}); err != nil {
			t.r.log.Debug("NEW_GROUP_REQUEST upstream failed", "track", t.name, "err", err)
		}
	}()
}

// downstream is one subscriber of a track.
type downstream struct {
	t *track
	w *moqt.TrackWriter

	startGroup  uint64
	startObject uint64  // within startGroup
	endGroup    *uint64 // inclusive
	liveOnly    bool    // no replay of cached Groups

	wg         sync.WaitGroup
	finishOnce sync.Once
	timeout    time.Duration // delivery timeout; <= 0 disables
}

// setFilter derives the delivery range from the LOCATION_FILTER. With no
// filter (or Next Object) only subgroups that start after the subscription
// are forwarded; Objects in already-open subgroups are skipped.
func (s *downstream) setFilter(p *v22.Params, largest *v22.Location) {
	var f *v22.LocationFilter
	if p != nil {
		f = p.LocationFilter
	}
	if f == nil {
		s.liveOnly = true
		return
	}
	switch f.Type {
	case v22.FilterNone, v22.FilterNextObject:
		s.liveOnly = true
	case v22.FilterRelativeStart:
		if largest != nil && f.StartGroup <= largest.Group+1 {
			s.startGroup = largest.Group + 1 - f.StartGroup
		}
	case v22.FilterAbsoluteStart:
		s.startGroup, s.startObject = f.StartGroup, f.StartObject
	case v22.FilterAbsoluteStartGroupEnd, v22.FilterAbsoluteRange:
		// EndObject of an absolute range is not applied; the whole end
		// Group is delivered.
		s.startGroup, s.startObject = f.StartGroup, f.StartObject
		end := f.StartGroup + f.EndGroupDelta
		s.endGroup = &end
	}
}

func (s *downstream) wants(group uint64) bool {
	if group < s.startGroup || (s.endGroup != nil && group > *s.endGroup) {
		return false
	}
	return s.w != nil && s.w.Forwarding()
}

func (s *downstream) firstObject(group uint64) uint64 {
	if group == s.startGroup {
		return s.startObject
	}
	return 0
}

func (s *downstream) startForward(sg *subgroup, from uint64) {
	s.wg.Add(1)
	go s.forward(sg, from)
}

// forward copies one cached subgroup to this subscriber, following the
// upstream: FIN when it finished, reset when it was reset.
func (s *downstream) forward(sg *subgroup, from uint64) {
	defer s.wg.Done()
	ctx := s.w.Context()
	var out *moqt.OutgoingSubgroup
	var outMu sync.Mutex
	done := make(chan struct{})
	defer close(done)
	if s.timeout > 0 {
		go s.watchStale(sg.group, done, func() {
			outMu.Lock()
			if out != nil {
				out.Reset(v22.ResetDeliveryTimeout)
			}
			outMu.Unlock()
		})
	}
	for i := 0; ; {
		o, state, changed := sg.at(i)
		if o != nil {
			i++
			if o.ID < from {
				continue
			}
			if !s.w.Forwarding() {
				// Paused (FORWARD=0): omit the rest of the subgroup, which
				// the spec requires signalling with a reset (Section 11.3.2).
				outMu.Lock()
				if out != nil {
					out.Reset(v22.ResetCancelled)
				}
				outMu.Unlock()
				return
			}
			if out == nil {
				id, _ := sg.subgroupID()
				opts := moqt.SubgroupOptions{
					Properties:  sg.header.Properties,
					EndOfGroup:  sg.header.EndOfGroup,
					FirstObject: sg.header.FirstObject && i == 1,
				}
				if sg.header.HasPriority {
					opts.Priority = new(sg.header.Priority)
				}
				outMu.Lock()
				out = s.w.OpenSubgroup(sg.group, id, opts)
				outMu.Unlock()
			}
			if err := out.WriteObject(o); err != nil {
				out.Reset(v22.ResetCancelled)
				return
			}
			continue
		}
		switch state {
		case sgFinished:
			if out != nil {
				out.Close()
			}
			return
		case sgReset:
			if out != nil {
				out.Reset(v22.ResetCancelled)
			}
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			if out != nil {
				out.Reset(v22.ResetCancelled)
			}
			return
		}
	}
}

// watchStale resets a subgroup (through reset) once it is still being
// sent s.timeout after a newer Group started, unless done closes first.
func (s *downstream) watchStale(group uint64, done <-chan struct{}, reset func()) {
	t := s.t
	for {
		t.mu.Lock()
		newer, at, changed := t.hasLive && t.liveGroup > group, t.liveAt, t.liveChanged
		t.mu.Unlock()
		if newer {
			timer := time.NewTimer(s.timeout - time.Since(at))
			defer timer.Stop()
			select {
			case <-timer.C:
				reset()
			case <-done:
			}
			return
		}
		select {
		case <-changed:
		case <-done:
			return
		}
	}
}

// watch handles the subscriber's REQUEST_UPDATEs and departure.
func (s *downstream) watch() {
	for {
		select {
		case p := <-s.w.Updates():
			if p.NewGroupRequest != nil {
				s.t.newGroupRequest(*p.NewGroupRequest)
			}
		case <-s.w.Context().Done():
			s.t.removeSubscriber(s)
			return
		}
	}
}

// finish sends PUBLISH_DONE once every stream for the subscription ended.
func (s *downstream) finish(code v22.PublishDoneCode, reason string) {
	s.finishOnce.Do(func() {
		go func() {
			s.wg.Wait()
			s.w.Close(code, reason)
		}()
	})
}
