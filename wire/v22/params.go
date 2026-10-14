package v22

import (
	"fmt"
	"slices"
)

// ParamType identifies a Message Parameter (Section 9.20, Table 14).
type ParamType uint64

const (
	ParamObjectDeliveryTimeout   ParamType = 0x02
	ParamAuthorizationToken      ParamType = 0x03
	ParamRendezvousTimeout       ParamType = 0x04
	ParamSubgroupDeliveryTimeout ParamType = 0x06
	ParamExpires                 ParamType = 0x08
	ParamLargestObject           ParamType = 0x09
	ParamFillTimeout             ParamType = 0x0A
	ParamForward                 ParamType = 0x10
	ParamSubscriberPriority      ParamType = 0x20
	ParamLocationFilter          ParamType = 0x21
	ParamGroupOrder              ParamType = 0x22
	ParamFillParameters          ParamType = 0x23
	ParamSubgroupFilter          ParamType = 0x25
	ParamObjectIDFilter          ParamType = 0x26
	ParamPriorityFilter          ParamType = 0x27
	ParamObjectPropertyFilter    ParamType = 0x28
	ParamTrackPropertyFilter     ParamType = 0x29
	ParamNewGroupRequest         ParamType = 0x32
	ParamTrackNamespacePrefix    ParamType = 0x34
	ParamIncludeProperties       ParamType = 0x35
)

// GroupOrder values (Section 9.20.8).
type GroupOrder uint8

const (
	GroupOrderAscending  GroupOrder = 0x1
	GroupOrderDescending GroupOrder = 0x2
)

// LocationFilterType selects the form of a Location Filter (Table 6).
type LocationFilterType uint64

const (
	FilterNone                  LocationFilterType = 0x00
	FilterRelativeStart         LocationFilterType = 0x01
	FilterAbsoluteStart         LocationFilterType = 0x02
	FilterAbsoluteStartGroupEnd LocationFilterType = 0x03
	FilterAbsoluteRange         LocationFilterType = 0x04
	FilterNextObject            LocationFilterType = 0x05
)

// LocationFilter carries the raw wire fields of a LOCATION_FILTER; which
// fields are meaningful depends on Type (Section 9.20.9).
type LocationFilter struct {
	Type          LocationFilterType
	StartGroup    uint64 // relative for FilterRelativeStart, absolute otherwise
	StartObject   uint64
	EndGroupDelta uint64
	EndObject     uint64
}

// Range is an inclusive range of values; only the last Range of a filter
// may be OpenEnded (Section 8.6).
type Range struct {
	Start, End uint64
	OpenEnded  bool
}

// RangeFilter is one of the Range Filter parameters 0x25-0x29 (Section 3.3.2).
// An empty Ranges slice encodes a zero Length, which removes the filter in
// REQUEST_UPDATE.
type RangeFilter struct {
	SetID        uint8
	PropertyType uint64 // only for OBJECT_PROPERTY_FILTER and TRACK_PROPERTY_FILTER
	Ranges       []Range
}

// Params holds the Message Parameters of one message. Optional scalar
// parameters are pointers; parameters that may repeat are slices.
type Params struct {
	ObjectDeliveryTimeout   *uint64 // ms
	AuthorizationTokens     []Token
	RendezvousTimeout       *uint64 // ms
	SubgroupDeliveryTimeout *uint64 // ms
	Expires                 *uint64 // ms
	LargestObject           *Location
	FillTimeout             *uint64 // ms
	Forward                 *uint8
	SubscriberPriority      *uint8
	LocationFilter          *LocationFilter
	GroupOrder              *GroupOrder
	FillParameters          *Params
	SubgroupFilters         []RangeFilter
	ObjectIDFilters         []RangeFilter
	PriorityFilters         []RangeFilter
	ObjectPropertyFilters   []RangeFilter
	TrackPropertyFilters    []RangeFilter
	NewGroupRequest         *uint64
	TrackNamespacePrefix    Namespace // nil when absent
	IncludeProperties       *uint8
}

// present lists the parameter types set in p, in ascending order, with
// repeats for repeatable parameters.
func (p *Params) present() []ParamType {
	var ts []ParamType
	add := func(cond bool, t ParamType) {
		if cond {
			ts = append(ts, t)
		}
	}
	add(p.ObjectDeliveryTimeout != nil, ParamObjectDeliveryTimeout)
	for range p.AuthorizationTokens {
		ts = append(ts, ParamAuthorizationToken)
	}
	add(p.RendezvousTimeout != nil, ParamRendezvousTimeout)
	add(p.SubgroupDeliveryTimeout != nil, ParamSubgroupDeliveryTimeout)
	add(p.Expires != nil, ParamExpires)
	add(p.LargestObject != nil, ParamLargestObject)
	add(p.FillTimeout != nil, ParamFillTimeout)
	add(p.Forward != nil, ParamForward)
	add(p.SubscriberPriority != nil, ParamSubscriberPriority)
	add(p.LocationFilter != nil, ParamLocationFilter)
	add(p.GroupOrder != nil, ParamGroupOrder)
	add(p.FillParameters != nil, ParamFillParameters)
	for range p.SubgroupFilters {
		ts = append(ts, ParamSubgroupFilter)
	}
	for range p.ObjectIDFilters {
		ts = append(ts, ParamObjectIDFilter)
	}
	for range p.PriorityFilters {
		ts = append(ts, ParamPriorityFilter)
	}
	for range p.ObjectPropertyFilters {
		ts = append(ts, ParamObjectPropertyFilter)
	}
	for range p.TrackPropertyFilters {
		ts = append(ts, ParamTrackPropertyFilter)
	}
	add(p.NewGroupRequest != nil, ParamNewGroupRequest)
	add(p.TrackNamespacePrefix != nil, ParamTrackNamespacePrefix)
	add(p.IncludeProperties != nil, ParamIncludeProperties)
	return ts
}

// check verifies that every parameter set in p is in allowed.
func (p *Params) check(allowed []ParamType, msg string) error {
	for _, t := range p.present() {
		if !slices.Contains(allowed, t) {
			return protocolViolation("parameter 0x%x not allowed in %s", uint64(t), msg)
		}
	}
	return nil
}

// appendParams encodes p as "Number of Parameters (vi64), Parameters".
func appendParams(b []byte, p *Params) ([]byte, error) {
	if p == nil {
		return AppendVarint(b, 0), nil
	}
	types := p.present()
	b = AppendVarint(b, uint64(len(types)))
	return appendParamValues(b, p, types)
}

func appendParamValues(b []byte, p *Params, types []ParamType) ([]byte, error) {
	var prev ParamType
	counts := map[ParamType]int{}
	var err error
	for _, t := range types {
		b = AppendVarint(b, uint64(t-prev))
		prev = t
		i := counts[t]
		counts[t]++
		switch t {
		case ParamObjectDeliveryTimeout:
			b = AppendVarint(b, *p.ObjectDeliveryTimeout)
		case ParamAuthorizationToken:
			b = appendLengthPrefixed(b, p.AuthorizationTokens[i].Append(nil))
		case ParamRendezvousTimeout:
			b = AppendVarint(b, *p.RendezvousTimeout)
		case ParamSubgroupDeliveryTimeout:
			b = AppendVarint(b, *p.SubgroupDeliveryTimeout)
		case ParamExpires:
			b = AppendVarint(b, *p.Expires)
		case ParamLargestObject:
			b = p.LargestObject.Append(b)
		case ParamFillTimeout:
			b = AppendVarint(b, *p.FillTimeout)
		case ParamForward:
			b = append(b, *p.Forward)
		case ParamSubscriberPriority:
			b = append(b, *p.SubscriberPriority)
		case ParamLocationFilter:
			b = p.LocationFilter.append(b)
		case ParamGroupOrder:
			b = append(b, byte(*p.GroupOrder))
		case ParamFillParameters:
			// The value is the nested parameters bounded by the length
			// prefix, without a count (Section 9.20.15 says "encoded as if
			// they were Parameters for a separate message"; the length
			// already bounds them). Revisit if peers disagree.
			inner, err := appendParamValues(nil, p.FillParameters, p.FillParameters.present())
			if err != nil {
				return nil, err
			}
			b = appendLengthPrefixed(b, inner)
		case ParamSubgroupFilter:
			b, err = p.SubgroupFilters[i].append(b, false)
		case ParamObjectIDFilter:
			b, err = p.ObjectIDFilters[i].append(b, false)
		case ParamPriorityFilter:
			b, err = p.PriorityFilters[i].append(b, false)
		case ParamObjectPropertyFilter:
			b, err = p.ObjectPropertyFilters[i].append(b, true)
		case ParamTrackPropertyFilter:
			b, err = p.TrackPropertyFilters[i].append(b, true)
		case ParamNewGroupRequest:
			b = AppendVarint(b, *p.NewGroupRequest)
		case ParamTrackNamespacePrefix:
			b = p.TrackNamespacePrefix.Append(b)
		case ParamIncludeProperties:
			b = append(b, *p.IncludeProperties)
		}
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Params decodes "Number of Parameters (vi64), Parameters".
func (d *Decoder) Params() *Params {
	n := d.Varint()
	if d.err != nil {
		return nil
	}
	p := &Params{}
	d.paramValues(p, func(i int) bool { return uint64(i) < n })
	return p
}

// paramValues decodes parameters into p while more reports true.
func (d *Decoder) paramValues(p *Params, more func(i int) bool) {
	var typ uint64
	for i := 0; d.err == nil && more(i); i++ {
		delta := d.Varint()
		if d.err != nil {
			return
		}
		if delta > MaxVarint-typ {
			d.fail(protocolViolation("parameter type overflow"))
			return
		}
		typ += delta
		t := ParamType(typ)
		if i > 0 && delta == 0 && !repeatable(t) {
			d.fail(protocolViolation("duplicate parameter 0x%x", typ))
			return
		}
		switch t {
		case ParamObjectDeliveryTimeout:
			p.ObjectDeliveryTimeout = new(d.Varint())
		case ParamAuthorizationToken:
			v := d.LengthPrefixed(MaxKeyValueBytes, "authorization token")
			if d.err == nil {
				tok, err := ParseToken(v)
				if err != nil {
					d.fail(err)
					return
				}
				p.AuthorizationTokens = append(p.AuthorizationTokens, tok)
			}
		case ParamRendezvousTimeout:
			// Encoding unstated in -22; varint like the other ms durations.
			p.RendezvousTimeout = new(d.Varint())
		case ParamSubgroupDeliveryTimeout:
			p.SubgroupDeliveryTimeout = new(d.Varint())
		case ParamExpires:
			p.Expires = new(d.Varint())
		case ParamLargestObject:
			p.LargestObject = new(d.Location())
		case ParamFillTimeout:
			// Encoding unstated in -22; varint like the other ms durations.
			p.FillTimeout = new(d.Varint())
		case ParamForward:
			v := d.Byte()
			if d.err == nil && v > 1 {
				d.fail(protocolViolation("FORWARD value %d", v))
			}
			p.Forward = new(v)
		case ParamSubscriberPriority:
			p.SubscriberPriority = new(d.Byte())
		case ParamLocationFilter:
			p.LocationFilter = d.locationFilter()
		case ParamGroupOrder:
			v := GroupOrder(d.Byte())
			if d.err == nil && v != GroupOrderAscending && v != GroupOrderDescending {
				d.fail(protocolViolation("GROUP_ORDER value %d", v))
			}
			p.GroupOrder = new(v)
		case ParamFillParameters:
			sub := d.Sub(d.Varint())
			inner := &Params{}
			sub.paramValues(inner, func(int) bool { return sub.Len() > 0 })
			if sub.err != nil {
				d.fail(sub.err)
				return
			}
			if err := inner.check(fillParams, "FILL_PARAMETERS"); err != nil {
				d.fail(err)
				return
			}
			p.FillParameters = inner
		case ParamSubgroupFilter:
			p.SubgroupFilters = append(p.SubgroupFilters, d.rangeFilter(false))
		case ParamObjectIDFilter:
			p.ObjectIDFilters = append(p.ObjectIDFilters, d.rangeFilter(false))
		case ParamPriorityFilter:
			p.PriorityFilters = append(p.PriorityFilters, d.rangeFilter(false))
		case ParamObjectPropertyFilter:
			p.ObjectPropertyFilters = append(p.ObjectPropertyFilters, d.rangeFilter(true))
		case ParamTrackPropertyFilter:
			p.TrackPropertyFilters = append(p.TrackPropertyFilters, d.rangeFilter(true))
		case ParamNewGroupRequest:
			p.NewGroupRequest = new(d.Varint())
		case ParamTrackNamespacePrefix:
			p.TrackNamespacePrefix = d.Namespace()
			if p.TrackNamespacePrefix == nil {
				p.TrackNamespacePrefix = Namespace{}
			}
		case ParamIncludeProperties:
			v := d.Byte()
			if d.err == nil && v > 1 {
				d.fail(protocolViolation("INCLUDE_PROPERTIES value %d", v))
			}
			p.IncludeProperties = new(v)
		default:
			d.fail(protocolViolation("unknown parameter 0x%x", typ))
			return
		}
	}
}

func repeatable(t ParamType) bool {
	switch t {
	case ParamAuthorizationToken, ParamSubgroupFilter, ParamObjectIDFilter,
		ParamPriorityFilter, ParamObjectPropertyFilter, ParamTrackPropertyFilter:
		return true
	}
	return false
}

func (f *LocationFilter) append(b []byte) []byte {
	b = AppendVarint(b, uint64(f.Type))
	switch f.Type {
	case FilterRelativeStart:
		b = AppendVarint(b, f.StartGroup)
	case FilterAbsoluteStart:
		b = AppendVarint(AppendVarint(b, f.StartGroup), f.StartObject)
	case FilterAbsoluteStartGroupEnd:
		b = AppendVarint(AppendVarint(AppendVarint(b, f.StartGroup), f.StartObject), f.EndGroupDelta)
	case FilterAbsoluteRange:
		b = AppendVarint(AppendVarint(AppendVarint(AppendVarint(b, f.StartGroup), f.StartObject), f.EndGroupDelta), f.EndObject)
	}
	return b
}

func (d *Decoder) locationFilter() *LocationFilter {
	f := &LocationFilter{Type: LocationFilterType(d.Varint())}
	switch f.Type {
	case FilterNone, FilterNextObject:
	case FilterRelativeStart:
		f.StartGroup = d.Varint()
	case FilterAbsoluteStart:
		f.StartGroup, f.StartObject = d.Varint(), d.Varint()
	case FilterAbsoluteStartGroupEnd:
		f.StartGroup, f.StartObject, f.EndGroupDelta = d.Varint(), d.Varint(), d.Varint()
	case FilterAbsoluteRange:
		f.StartGroup, f.StartObject, f.EndGroupDelta, f.EndObject = d.Varint(), d.Varint(), d.Varint(), d.Varint()
	default:
		d.fail(protocolViolation("location filter type %d", f.Type))
	}
	if d.err == nil && f.EndGroupDelta > MaxVarint-f.StartGroup {
		d.fail(protocolViolation("location filter end group overflow"))
	}
	return f
}

func (f *RangeFilter) append(b []byte, withProperty bool) ([]byte, error) {
	if len(f.Ranges) == 0 {
		return AppendVarint(b, 0), nil
	}
	body := []byte{f.SetID}
	if withProperty {
		body = AppendVarint(body, f.PropertyType)
	}
	var prevEnd uint64
	for i, r := range f.Ranges {
		if r.Start < prevEnd || (!r.OpenEnded && r.End < r.Start) {
			return nil, fmt.Errorf("range filter ranges must be ascending and non-overlapping")
		}
		if r.OpenEnded && i != len(f.Ranges)-1 {
			return nil, fmt.Errorf("only the last range may be open-ended")
		}
		body = AppendVarint(body, r.Start-prevEnd)
		if !r.OpenEnded {
			body = AppendVarint(body, r.End-r.Start)
			prevEnd = r.End
		}
	}
	return appendLengthPrefixed(b, body), nil
}

func (d *Decoder) rangeFilter(withProperty bool) RangeFilter {
	sub := d.Sub(d.Varint())
	var f RangeFilter
	if sub.Len() == 0 {
		return f
	}
	f.SetID = sub.Byte()
	if withProperty {
		f.PropertyType = sub.Varint()
	}
	var prevEnd uint64
	for sub.err == nil && sub.Len() > 0 {
		delta := sub.Varint()
		if delta > MaxVarint-prevEnd {
			sub.fail(protocolViolation("range start overflow"))
			break
		}
		r := Range{Start: prevEnd + delta}
		if sub.Len() == 0 {
			r.OpenEnded = true
		} else {
			delta = sub.Varint()
			if delta > MaxVarint-r.Start {
				sub.fail(protocolViolation("range end overflow"))
				break
			}
			r.End = r.Start + delta
			prevEnd = r.End
		}
		f.Ranges = append(f.Ranges, r)
	}
	if sub.err != nil {
		d.fail(sub.err)
	}
	return f
}

// Parameters allowed per message (Section 9).
var (
	subscribeParams = []ParamType{ParamObjectDeliveryTimeout, ParamAuthorizationToken, ParamRendezvousTimeout,
		ParamSubgroupDeliveryTimeout, ParamForward, ParamSubscriberPriority, ParamLocationFilter, ParamGroupOrder,
		ParamFillParameters, ParamSubgroupFilter, ParamObjectIDFilter, ParamPriorityFilter, ParamObjectPropertyFilter,
		ParamNewGroupRequest, ParamIncludeProperties}
	subscribeOKParams = []ParamType{ParamExpires, ParamLargestObject}
	publishParams     = []ParamType{ParamObjectDeliveryTimeout, ParamAuthorizationToken, ParamSubgroupDeliveryTimeout,
		ParamExpires, ParamLargestObject, ParamForward, ParamSubscriberPriority, ParamLocationFilter, ParamGroupOrder}
	publishStateNotifyParams = []ParamType{ParamLargestObject, ParamForward, ParamLocationFilter}
	fetchParams              = []ParamType{ParamAuthorizationToken, ParamFillTimeout, ParamSubscriberPriority,
		ParamLocationFilter, ParamGroupOrder, ParamSubgroupFilter, ParamObjectIDFilter, ParamPriorityFilter,
		ParamObjectPropertyFilter, ParamIncludeProperties}
	fetchOKParams          = []ParamType{}
	trackStatusParams      = []ParamType{ParamAuthorizationToken, ParamIncludeProperties}
	namespaceRequestParams = []ParamType{ParamAuthorizationToken}
	subscribeTracksParams  = []ParamType{ParamAuthorizationToken, ParamForward, ParamGroupOrder, ParamSubgroupFilter,
		ParamObjectIDFilter, ParamPriorityFilter, ParamObjectPropertyFilter, ParamTrackPropertyFilter, ParamIncludeProperties}
	// REQUEST_OK and REQUEST_UPDATE carry the union of what their request
	// types allow; the session layer narrows it by request type.
	requestOKParams     = []ParamType{ParamExpires, ParamLargestObject}
	requestUpdateParams = []ParamType{ParamObjectDeliveryTimeout, ParamAuthorizationToken, ParamSubgroupDeliveryTimeout,
		ParamForward, ParamSubscriberPriority, ParamLocationFilter, ParamFillParameters, ParamSubgroupFilter,
		ParamObjectIDFilter, ParamPriorityFilter, ParamObjectPropertyFilter, ParamTrackPropertyFilter,
		ParamNewGroupRequest, ParamTrackNamespacePrefix}
	fillParams = []ParamType{ParamFillTimeout, ParamSubscriberPriority, ParamLocationFilter, ParamGroupOrder,
		ParamSubgroupFilter, ParamObjectIDFilter, ParamPriorityFilter, ParamObjectPropertyFilter}
)
