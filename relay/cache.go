package relay

import (
	"sync"

	v22 "github.com/MoQ-it/moqt/wire/v22"
)

type subgroupState uint8

const (
	sgOpen     subgroupState = iota
	sgFinished               // upstream FIN: every Object was delivered
	sgReset                  // upstream reset: later Objects may exist
)

// subgroup buffers the Objects of one upstream subgroup stream. It is the
// fan-out point: each downstream subscriber reads it with its own cursor,
// so a slow subscriber never holds up the others.
type subgroup struct {
	group  uint64
	header *v22.SubgroupHeader

	mu      sync.Mutex
	idKnown bool
	id      uint64
	objects []*v22.Object
	state   subgroupState
	changed chan struct{} // closed and replaced whenever anything changes
}

func newSubgroup(group uint64, hdr *v22.SubgroupHeader) *subgroup {
	sg := &subgroup{group: group, header: hdr, changed: make(chan struct{})}
	switch hdr.IDMode {
	case v22.SubgroupIDZero:
		sg.idKnown = true
	case v22.SubgroupIDExplicit:
		sg.idKnown, sg.id = true, hdr.SubgroupID
	}
	return sg
}

func (sg *subgroup) notifyLocked() {
	close(sg.changed)
	sg.changed = make(chan struct{})
}

func (sg *subgroup) append(o *v22.Object) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if !sg.idKnown {
		sg.idKnown, sg.id = true, o.ID
	}
	sg.objects = append(sg.objects, o)
	sg.notifyLocked()
}

func (sg *subgroup) end(state subgroupState) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if sg.state == sgOpen {
		sg.state = state
		sg.notifyLocked()
	}
}

// at returns Object i if it has arrived; otherwise the subgroup's state and
// a channel that closes on the next change.
func (sg *subgroup) at(i int) (*v22.Object, subgroupState, <-chan struct{}) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if i < len(sg.objects) {
		return sg.objects[i], sg.state, nil
	}
	return nil, sg.state, sg.changed
}

// subgroupID returns the Subgroup ID once known (after the first Object
// for SubgroupIDFirstObject).
func (sg *subgroup) subgroupID() (uint64, bool) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	return sg.id, sg.idKnown
}

// group is one cached Group.
type group struct {
	id        uint64
	subgroups []*subgroup
}
