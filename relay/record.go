package relay

import (
	"sync"

	"github.com/MoQ-it/moqt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
)

// Recorder receives the Objects of a recorded track.
type Recorder interface {
	// RecordObject is called for each Object received from upstream, in
	// order within its subgroup. It must not modify o or block for long.
	RecordObject(group, subgroupID uint64, priority uint8, o *v22.Object)
	// RecordEnd is called once when the upstream subscription ends; call
	// Record again to resume once the track is published again.
	RecordEnd()
}

type recording struct {
	rec     Recorder
	endOnce sync.Once
}

func (rec *recording) end() { rec.endOnce.Do(rec.rec.RecordEnd) }

// Record keeps the track's upstream subscription open, with or without
// subscribers, and passes every Object to rec until stop is called or the
// upstream subscription ends. It asks the publisher for a new Group so
// recording starts on a fresh one. It returns the Track Properties.
func (r *Relay) Record(name v22.FullTrackName, rec Recorder) (props v22.KeyValues, stop func(), err error) {
	rg := &recording{rec: rec}
	for range 2 {
		attached := false
		t, err := r.track(name, &v22.Params{NewGroupRequest: new(uint64(0))}, func(t *track) {
			t.recs[rg] = struct{}{}
			if t.linger != nil {
				t.linger.Stop()
				t.linger = nil
			}
			attached = true
		})
		if err != nil {
			return nil, nil, err
		}
		if !attached {
			continue // closed meanwhile
		}
		stop := func() {
			t.mu.Lock()
			_, ok := t.recs[rg]
			delete(t.recs, rg)
			t.mu.Unlock()
			if ok {
				t.maybeLinger()
			}
		}
		return t.props, stop, nil
	}
	return nil, nil, &moqt.RequestError{Code: v22.ReqErrInternal, Reason: "track closed"}
}

func (t *track) record(sg *subgroup, o *v22.Object) {
	t.mu.Lock()
	if len(t.recs) == 0 {
		t.mu.Unlock()
		return
	}
	recs := make([]*recording, 0, len(t.recs))
	for rg := range t.recs {
		recs = append(recs, rg)
	}
	t.mu.Unlock()
	prio := t.info.PublisherPriority
	if sg.header.HasPriority {
		prio = sg.header.Priority
	}
	id, _ := sg.subgroupID()
	for _, rg := range recs {
		rg.rec.RecordObject(sg.group, id, prio, o)
	}
}
