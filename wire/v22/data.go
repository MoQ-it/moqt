package v22

import (
	"errors"
	"io"
)

// Unidirectional stream and datagram types (Section 6.4.1, 11).
const (
	StreamTypeFetch   = 0x05
	StreamTypeSetup   = uint64(MsgSetup)
	StreamTypePadding = 0x132B3E28
	DatagramPadding   = 0x132B3E29
)

// IsSubgroupStreamType reports whether a unidirectional stream type is a
// SUBGROUP_HEADER (0b0XX1XXXX, Section 11.3.1).
func IsSubgroupStreamType(t uint64) bool { return t < 0x80 && t&0x10 != 0 }

// ObjectStatus (Section 11.1.1).
type ObjectStatus uint64

const (
	StatusNormal     ObjectStatus = 0x0
	StatusEndOfGroup ObjectStatus = 0x3
	StatusEndOfTrack ObjectStatus = 0x4
)

func (s ObjectStatus) valid() bool {
	return s == StatusNormal || s == StatusEndOfGroup || s == StatusEndOfTrack
}

func appendObjectProperties(b []byte, props KeyValues) []byte {
	return appendLengthPrefixed(b, props.Append(nil))
}

func (d *Decoder) objectProperties() KeyValues {
	sub := d.Sub(d.Varint())
	kvs := sub.KeyValues()
	if sub.err != nil {
		d.fail(sub.err)
	}
	return kvs
}

// Datagram flags (Section 11.2.1).
const (
	dgProperties      = 0x01
	dgEndOfGroup      = 0x02
	dgZeroObjectID    = 0x04
	dgDefaultPriority = 0x08
	dgReserved        = 0x10
	dgStatus          = 0x20
	dgKnown           = dgProperties | dgEndOfGroup | dgZeroObjectID | dgDefaultPriority | dgStatus
)

// Datagram is an OBJECT_DATAGRAM.
type Datagram struct {
	TrackAlias  uint64
	Group       uint64
	Object      uint64
	HasPriority bool // false: inherit the subscription's publisher priority
	Priority    uint8
	Properties  KeyValues
	// EndOfGroup says no later Object exists in this Group.
	EndOfGroup bool
	Status     ObjectStatus
	Payload    []byte
}

// AppendDatagram encodes d. A non-Normal status or an empty payload is
// sent in the STATUS form.
func AppendDatagram(b []byte, d *Datagram) ([]byte, error) {
	statusForm := d.Status != StatusNormal || len(d.Payload) == 0
	if d.Status != StatusNormal && (len(d.Payload) > 0 || len(d.Properties) > 0 || d.EndOfGroup) {
		return nil, errors.New("non-Normal datagram cannot carry payload, properties or the END_OF_GROUP flag")
	}
	if !d.Status.valid() {
		return nil, errors.New("invalid object status")
	}
	var flags uint64
	if len(d.Properties) > 0 {
		flags |= dgProperties
	}
	if d.EndOfGroup {
		if statusForm {
			// END_OF_GROUP and STATUS are mutually exclusive; signal an
			// empty last Object by its End of Group status instead.
			return nil, errors.New("empty datagram cannot set END_OF_GROUP; send an End of Group status object")
		}
		flags |= dgEndOfGroup
	}
	if d.Object == 0 {
		flags |= dgZeroObjectID
	}
	if !d.HasPriority {
		flags |= dgDefaultPriority
	}
	if statusForm {
		flags |= dgStatus
	}
	b = AppendVarint(AppendVarint(AppendVarint(b, flags), d.TrackAlias), d.Group)
	if d.Object != 0 {
		b = AppendVarint(b, d.Object)
	}
	if d.HasPriority {
		b = append(b, d.Priority)
	}
	if len(d.Properties) > 0 {
		b = appendObjectProperties(b, d.Properties)
	}
	if statusForm {
		return AppendVarint(b, uint64(d.Status)), nil
	}
	return append(b, d.Payload...), nil
}

// ErrPaddingDatagram is returned by ParseDatagram for padding, which the
// caller discards.
var ErrPaddingDatagram = errors.New("padding datagram")

// ParseDatagram decodes an OBJECT_DATAGRAM. The payload aliases b.
func ParseDatagram(b []byte) (*Datagram, error) {
	d := NewDecoder(b)
	flags := d.Varint()
	if d.err == nil && flags == DatagramPadding {
		return nil, ErrPaddingDatagram
	}
	if d.err == nil && (flags >= 0x80 || flags&^dgKnown != 0 || flags&dgReserved != 0 ||
		flags&(dgStatus|dgEndOfGroup) == dgStatus|dgEndOfGroup) {
		return nil, protocolViolation("invalid datagram type 0x%x", flags)
	}
	dg := &Datagram{
		TrackAlias: d.Varint(),
		Group:      d.Varint(),
		EndOfGroup: flags&dgEndOfGroup != 0,
	}
	if flags&dgZeroObjectID == 0 {
		dg.Object = d.Varint()
	}
	if flags&dgDefaultPriority == 0 {
		dg.HasPriority = true
		dg.Priority = d.Byte()
	}
	if flags&dgProperties != 0 {
		n := d.Varint()
		if d.err == nil && n == 0 {
			return nil, protocolViolation("datagram PROPERTIES flag with empty properties")
		}
		sub := d.Sub(n)
		dg.Properties = sub.KeyValues()
		if sub.err != nil {
			d.fail(sub.err)
		}
	}
	if flags&dgStatus != 0 {
		dg.Status = ObjectStatus(d.Varint())
		if d.err == nil && !dg.Status.valid() {
			return nil, protocolViolation("object status 0x%x", uint64(dg.Status))
		}
		if d.err == nil && dg.Status != StatusNormal && len(dg.Properties) > 0 {
			return nil, protocolViolation("properties on a non-Normal object")
		}
		if d.err == nil && d.Len() > 0 {
			return nil, protocolViolation("datagram has bytes after its status")
		}
	} else {
		dg.Payload = d.Rest()
	}
	if err := d.Err(); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, protocolViolation("truncated datagram")
		}
		return nil, err
	}
	return dg, nil
}

// SubgroupIDMode says how the Subgroup ID is conveyed (Section 11.3.1).
type SubgroupIDMode uint8

const (
	SubgroupIDZero        SubgroupIDMode = 0b00
	SubgroupIDFirstObject SubgroupIDMode = 0b01
	SubgroupIDExplicit    SubgroupIDMode = 0b10
)

// Subgroup header flags.
const (
	sgProperties      = 0x01
	sgIDModeMask      = 0x06
	sgEndOfGroup      = 0x08
	sgAlwaysSet       = 0x10
	sgDefaultPriority = 0x20
	sgFirstObject     = 0x40
)

// SubgroupHeader starts a subgroup data stream.
type SubgroupHeader struct {
	TrackAlias  uint64
	Group       uint64
	IDMode      SubgroupIDMode
	SubgroupID  uint64 // only with SubgroupIDExplicit
	HasPriority bool
	Priority    uint8
	// Properties says every Object on the stream carries a Properties field.
	Properties bool
	// EndOfGroup says this subgroup holds the Group's largest Object.
	EndOfGroup bool
	// FirstObject says the first Object on the stream is the first one the
	// original publisher sent in this subgroup.
	FirstObject bool
}

func (h *SubgroupHeader) flags() uint64 {
	f := uint64(sgAlwaysSet) | uint64(h.IDMode)<<1
	if h.Properties {
		f |= sgProperties
	}
	if h.EndOfGroup {
		f |= sgEndOfGroup
	}
	if !h.HasPriority {
		f |= sgDefaultPriority
	}
	if h.FirstObject {
		f |= sgFirstObject
	}
	return f
}

// Append encodes the header including its stream type.
func (h *SubgroupHeader) Append(b []byte) []byte {
	b = AppendVarint(AppendVarint(AppendVarint(b, h.flags()), h.TrackAlias), h.Group)
	if h.IDMode == SubgroupIDExplicit {
		b = AppendVarint(b, h.SubgroupID)
	}
	if h.HasPriority {
		b = append(b, h.Priority)
	}
	return b
}

// ReadSubgroupHeader decodes a SUBGROUP_HEADER whose stream type (the
// flags) has already been read.
func ReadSubgroupHeader(r StreamReader, streamType uint64) (*SubgroupHeader, error) {
	if !IsSubgroupStreamType(streamType) || (streamType&sgIDModeMask)>>1 == 0b11 {
		return nil, protocolViolation("invalid subgroup header type 0x%x", streamType)
	}
	h := &SubgroupHeader{
		IDMode:      SubgroupIDMode((streamType & sgIDModeMask) >> 1),
		Properties:  streamType&sgProperties != 0,
		EndOfGroup:  streamType&sgEndOfGroup != 0,
		HasPriority: streamType&sgDefaultPriority == 0,
		FirstObject: streamType&sgFirstObject != 0,
	}
	var err error
	if h.TrackAlias, err = ReadVarint(r); err != nil {
		return nil, unexpectedEOF(err)
	}
	if h.Group, err = ReadVarint(r); err != nil {
		return nil, unexpectedEOF(err)
	}
	if h.IDMode == SubgroupIDExplicit {
		if h.SubgroupID, err = ReadVarint(r); err != nil {
			return nil, unexpectedEOF(err)
		}
	}
	if h.HasPriority {
		if h.Priority, err = r.ReadByte(); err != nil {
			return nil, unexpectedEOF(err)
		}
	}
	return h, nil
}

// Object is one Object on a subgroup stream.
type Object struct {
	ID         uint64
	Properties KeyValues
	Status     ObjectStatus
	Payload    []byte
}

// SubgroupWriter encodes the Objects of one subgroup stream, tracking the
// delta encoding of Object IDs.
type SubgroupWriter struct {
	Header  *SubgroupHeader
	started bool
	prevID  uint64
}

// AppendObject encodes o. Object IDs must increase along the stream.
func (w *SubgroupWriter) AppendObject(b []byte, o *Object) ([]byte, error) {
	var delta uint64
	if w.started {
		if o.ID <= w.prevID {
			return nil, errors.New("subgroup object IDs must increase")
		}
		delta = o.ID - w.prevID - 1
	} else {
		delta = o.ID
	}
	if !o.Status.valid() || (o.Status != StatusNormal && (len(o.Payload) > 0 || len(o.Properties) > 0)) {
		return nil, errors.New("non-Normal objects have no payload or properties")
	}
	if len(o.Properties) > 0 && !w.Header.Properties {
		return nil, errors.New("subgroup header does not carry properties")
	}
	w.started, w.prevID = true, o.ID
	b = AppendVarint(b, delta)
	if w.Header.Properties {
		b = appendObjectProperties(b, o.Properties)
	}
	b = AppendVarint(b, uint64(len(o.Payload)))
	if len(o.Payload) == 0 {
		return AppendVarint(b, uint64(o.Status)), nil
	}
	return append(b, o.Payload...), nil
}

// MaxObjectPayload and MaxObjectProperties bound allocations when reading
// streams. MOQT sets no limit on either, so these protect receivers from
// peer-chosen lengths.
var (
	MaxObjectPayload    uint64 = 16 << 20
	MaxObjectProperties uint64 = 256 << 10
)

// readObjectProperties reads an Object Properties block of length n.
func readObjectProperties(r StreamReader, n uint64) (KeyValues, error) {
	if n > MaxObjectProperties {
		return nil, protocolViolation("object properties of %d bytes exceed the receive limit", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, midObject(err)
	}
	d := NewDecoder(buf)
	kvs := d.KeyValues()
	return kvs, d.Err()
}

// SubgroupReader decodes the Objects that follow a SUBGROUP_HEADER.
type SubgroupReader struct {
	r       StreamReader
	Header  *SubgroupHeader
	started bool
	prevID  uint64
}

func NewSubgroupReader(r StreamReader, h *SubgroupHeader) *SubgroupReader {
	return &SubgroupReader{r: r, Header: h}
}

// Next returns the next Object, or io.EOF when the stream ends cleanly
// between Objects. A FIN inside an Object is a protocol violation.
func (s *SubgroupReader) Next() (*Object, error) {
	delta, err := ReadVarint(s.r)
	if err != nil {
		return nil, err // io.EOF here is the clean end of the subgroup
	}
	o := &Object{}
	if s.started {
		if delta > MaxVarint-s.prevID-1 {
			return nil, protocolViolation("object ID overflow")
		}
		o.ID = s.prevID + delta + 1
	} else {
		o.ID = delta
	}
	s.started, s.prevID = true, o.ID
	if s.Header.Properties {
		n, err := ReadVarint(s.r)
		if err != nil {
			return nil, midObject(err)
		}
		if o.Properties, err = readObjectProperties(s.r, n); err != nil {
			return nil, err
		}
	}
	n, err := ReadVarint(s.r)
	if err != nil {
		return nil, midObject(err)
	}
	if n == 0 {
		st, err := ReadVarint(s.r)
		if err != nil {
			return nil, midObject(err)
		}
		o.Status = ObjectStatus(st)
		if !o.Status.valid() {
			return nil, protocolViolation("object status 0x%x", st)
		}
		if o.Status != StatusNormal && len(o.Properties) > 0 {
			return nil, protocolViolation("properties on a non-Normal object")
		}
		return o, nil
	}
	if n > MaxObjectPayload {
		return nil, protocolViolation("object payload of %d bytes exceeds the receive limit", n)
	}
	o.Payload = make([]byte, n)
	if _, err := io.ReadFull(s.r, o.Payload); err != nil {
		return nil, midObject(err)
	}
	return o, nil
}

// midObject maps a clean FIN inside an Object to a protocol violation and
// passes other errors (such as a stream reset) through.
func midObject(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return protocolViolation("stream ended inside an object")
	}
	return err
}

// FetchHeader starts a fetch data stream (Section 11.4.1).
type FetchHeader struct {
	RequestID uint64
}

func (h FetchHeader) Append(b []byte) []byte {
	return AppendVarint(AppendVarint(b, StreamTypeFetch), h.RequestID)
}

// FetchRangeKind marks an End of Range entry on a fetch stream (Table 8).
type FetchRangeKind uint64

const (
	FetchObjectEntry      FetchRangeKind = 0
	FetchRangeNonExistent FetchRangeKind = 0x8C
	FetchRangeUnknown     FetchRangeKind = 0x10C
	FetchRangeTimedOut    FetchRangeKind = 0x20C
)

// Fetch serialization flags (Section 11.4.1.1).
const (
	ffSubgroupMask    = 0x03
	ffSubgroupZero    = 0x00
	ffSubgroupPrior   = 0x01
	ffSubgroupNext    = 0x02
	ffSubgroupPresent = 0x03
	ffObjectDelta     = 0x04
	ffGroupDelta      = 0x08
	ffPriority        = 0x10
	ffProperties      = 0x20
	ffDatagram        = 0x40
)

// FetchObject is one entry on a fetch stream: an Object, or (when Range is
// set) an End of Range marker covering everything since the last entry up
// to and including Group/Object.
type FetchObject struct {
	Range      FetchRangeKind
	Group      uint64
	Object     uint64
	Datagram   bool // the Object had Delivery Mode Datagram and no Subgroup
	SubgroupID uint64
	Priority   uint8
	Properties KeyValues
	Payload    []byte
}

// fetchState tracks the "prior Object" that fetch encoding refers to.
type fetchState struct {
	descending bool
	started    bool // any entry, including range markers, seen
	haveObject bool // a real Object seen (for subgroup/priority references)
	group, obj uint64
	subgroup   uint64
	priority   uint8
}

// FetchWriter encodes the entries of one fetch stream.
type FetchWriter struct{ st fetchState }

// NewFetchWriter returns a writer for a fetch answered in the given order.
func NewFetchWriter(order GroupOrder) *FetchWriter {
	return &FetchWriter{st: fetchState{descending: order == GroupOrderDescending}}
}

func (w *FetchWriter) Append(b []byte, o *FetchObject) ([]byte, error) {
	st := &w.st
	if o.Range != FetchObjectEntry {
		switch o.Range {
		case FetchRangeNonExistent, FetchRangeUnknown, FetchRangeTimedOut:
		default:
			return nil, errors.New("unknown fetch range kind")
		}
		// End of Range markers carry absolute Group and Object IDs. Read
		// as deltas a marker could not end inside the current group; this
		// matches floatdrop/moq-go's draft-22 implementation.
		b = AppendVarint(AppendVarint(AppendVarint(b, uint64(o.Range)), o.Group), o.Object)
		st.started, st.group, st.obj = true, o.Group, o.Object
		return b, nil
	}
	var flags uint64
	var groupDelta, objDelta uint64
	if !st.started {
		flags |= ffGroupDelta | ffObjectDelta
		groupDelta, objDelta = o.Group, o.Object
	} else {
		if o.Group != st.group {
			flags |= ffGroupDelta
			switch {
			case !st.descending && o.Group > st.group:
				groupDelta = o.Group - st.group - 1
			case st.descending && o.Group < st.group:
				groupDelta = st.group - o.Group - 1
			default:
				return nil, errors.New("fetch groups must follow the fetch's group order")
			}
			flags |= ffObjectDelta
			objDelta = o.Object
		} else if o.Object != st.obj+1 {
			if o.Object <= st.obj {
				return nil, errors.New("fetch objects within a group must increase")
			}
			flags |= ffObjectDelta
			objDelta = o.Object - st.obj
		}
	}
	switch {
	case o.Datagram:
		flags |= ffDatagram
	case o.SubgroupID == 0:
		flags |= ffSubgroupZero
	case st.haveObject && o.SubgroupID == st.subgroup:
		flags |= ffSubgroupPrior
	case st.haveObject && o.SubgroupID == st.subgroup+1:
		flags |= ffSubgroupNext
	default:
		flags |= ffSubgroupPresent
	}
	if !st.haveObject || o.Priority != st.priority {
		flags |= ffPriority
	}
	if len(o.Properties) > 0 {
		flags |= ffProperties
	}
	b = AppendVarint(b, flags)
	if flags&ffGroupDelta != 0 {
		b = AppendVarint(b, groupDelta)
	}
	if !o.Datagram && flags&ffSubgroupMask == ffSubgroupPresent {
		b = AppendVarint(b, o.SubgroupID)
	}
	if flags&ffObjectDelta != 0 {
		b = AppendVarint(b, objDelta)
	}
	if flags&ffPriority != 0 {
		b = append(b, o.Priority)
	}
	if flags&ffProperties != 0 {
		b = appendObjectProperties(b, o.Properties)
	}
	b = appendLengthPrefixed(b, o.Payload)
	st.started, st.haveObject = true, true
	st.group, st.obj, st.priority = o.Group, o.Object, o.Priority
	if !o.Datagram {
		st.subgroup = o.SubgroupID
	}
	return b, nil
}

// FetchReader decodes the entries after a FETCH_HEADER.
type FetchReader struct {
	r  StreamReader
	st fetchState
}

// NewFetchReader reads a fetch stream answered in the given group order.
func NewFetchReader(r StreamReader, order GroupOrder) *FetchReader {
	return &FetchReader{r: r, st: fetchState{descending: order == GroupOrderDescending}}
}

// Next returns the next entry, or io.EOF at the clean end of the stream.
func (f *FetchReader) Next() (*FetchObject, error) {
	st := &f.st
	flags, err := ReadVarint(f.r)
	if err != nil {
		return nil, err
	}
	o := &FetchObject{}
	read := func() (uint64, error) {
		v, err := ReadVarint(f.r)
		return v, midObject(err)
	}
	if flags >= 0x80 {
		switch FetchRangeKind(flags) {
		case FetchRangeNonExistent, FetchRangeUnknown, FetchRangeTimedOut:
		default:
			return nil, protocolViolation("fetch serialization flags 0x%x", flags)
		}
		// Absolute Group and Object IDs; see FetchWriter.Append.
		o.Range = FetchRangeKind(flags)
		if o.Group, err = read(); err != nil {
			return nil, err
		}
		if o.Object, err = read(); err != nil {
			return nil, err
		}
		st.started, st.group, st.obj = true, o.Group, o.Object
		return o, nil
	}
	if !st.started && flags&(ffGroupDelta|ffObjectDelta) != ffGroupDelta|ffObjectDelta {
		return nil, protocolViolation("first fetch entry must carry group and object")
	}
	group, obj := st.group, st.obj
	if flags&ffGroupDelta != 0 {
		delta, err := read()
		if err != nil {
			return nil, err
		}
		switch {
		case !st.started:
			group = delta
		case st.descending:
			if delta >= st.group {
				return nil, protocolViolation("fetch group underflow")
			}
			group = st.group - delta - 1
		default:
			if delta > MaxVarint-st.group-1 {
				return nil, protocolViolation("fetch group overflow")
			}
			group = st.group + delta + 1
		}
	}
	if flags&ffDatagram == 0 {
		switch flags & ffSubgroupMask {
		case ffSubgroupZero:
			o.SubgroupID = 0
		case ffSubgroupPrior, ffSubgroupNext:
			if !st.haveObject {
				return nil, protocolViolation("fetch entry references a prior subgroup that does not exist")
			}
			o.SubgroupID = st.subgroup + (flags & ffSubgroupMask) - 1
		case ffSubgroupPresent:
			if o.SubgroupID, err = read(); err != nil {
				return nil, err
			}
		}
	}
	o.Datagram = flags&ffDatagram != 0
	if flags&ffObjectDelta != 0 {
		delta, err := read()
		if err != nil {
			return nil, err
		}
		if !st.started || flags&ffGroupDelta != 0 {
			obj = delta
		} else {
			if delta > MaxVarint-st.obj {
				return nil, protocolViolation("fetch object overflow")
			}
			obj = st.obj + delta
		}
	} else {
		if st.obj == MaxVarint {
			return nil, protocolViolation("fetch object overflow")
		}
		obj = st.obj + 1
	}
	o.Group, o.Object = group, obj
	st.started, st.group, st.obj = true, group, obj
	if flags&ffPriority != 0 {
		p, err := f.r.ReadByte()
		if err != nil {
			return nil, midObject(err)
		}
		o.Priority = p
	} else {
		if !st.haveObject {
			return nil, protocolViolation("fetch entry references a prior priority that does not exist")
		}
		o.Priority = st.priority
	}
	if flags&ffProperties != 0 {
		n, err := read()
		if err != nil {
			return nil, err
		}
		if o.Properties, err = readObjectProperties(f.r, n); err != nil {
			return nil, err
		}
	}
	n, err := read()
	if err != nil {
		return nil, err
	}
	if n > MaxObjectPayload {
		return nil, protocolViolation("object payload of %d bytes exceeds the receive limit", n)
	}
	if n > 0 {
		o.Payload = make([]byte, n)
		if _, err := io.ReadFull(f.r, o.Payload); err != nil {
			return nil, midObject(err)
		}
	}
	st.haveObject, st.priority = true, o.Priority
	if !o.Datagram {
		st.subgroup = o.SubgroupID
	}
	return o, nil
}
