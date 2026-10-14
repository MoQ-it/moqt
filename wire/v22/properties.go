package v22

// Track and Object Property types defined by MOQT (Section 10). Properties
// are Key-Value-Pairs: even types carry an integer, odd types bytes.
const (
	PropObjectDeliveryTimeout      = 0x02 // Track and Object, ms
	PropMaxCacheDuration           = 0x04 // Track, ms
	PropSubgroupDeliveryTimeout    = 0x06 // Track and Object, ms
	PropImmutable                  = 0x0B // Track and Object; value is nested Key-Value-Pairs
	PropDefaultPublisherPriority   = 0x0E // Track, 0-255
	PropDefaultPublisherGroupOrder = 0x22 // Track, 1 ascending / 2 descending
	PropDynamicGroups              = 0x30 // Track, 0 or 1
	PropPriorGroupIDGap            = 0x3C // Object
	PropPriorObjectIDGap           = 0x3E // Object
)

// Application-reserved property ranges that IANA will never allocate
// (Section 8.4).
func IsApplicationProperty(t uint64) bool {
	return (t >= 0x78 && t <= 0x7F) || (t >= 0x3800 && t <= 0x3FFF)
}

// Lookup returns the value of an integer property, searching the mutable
// properties first and then the contents of Immutable Properties, as
// Section 10.7 requires.
func (kvs KeyValues) Lookup(typ uint64) (KeyValue, bool) {
	if kv, ok := kvs.Get(typ); ok {
		return kv, true
	}
	if imm, ok := kvs.Get(PropImmutable); ok {
		d := NewDecoder(imm.Bytes)
		inner := d.KeyValues()
		if d.Err() == nil {
			return inner.Get(typ)
		}
	}
	return KeyValue{}, false
}

// TrackInfo is the subset of Track Properties the transport acts on.
type TrackInfo struct {
	PublisherPriority uint8
	GroupOrder        GroupOrder
	DynamicGroups     bool
}

// ParseTrackInfo extracts transport-relevant Track Properties, applying the
// defaults from Section 10 and rejecting out-of-range values.
func ParseTrackInfo(props KeyValues) (TrackInfo, error) {
	info := TrackInfo{PublisherPriority: 128, GroupOrder: GroupOrderAscending}
	if kv, ok := props.Lookup(PropDefaultPublisherPriority); ok {
		if kv.Int > 255 {
			return info, protocolViolation("default publisher priority %d", kv.Int)
		}
		info.PublisherPriority = uint8(kv.Int)
	}
	if kv, ok := props.Lookup(PropDefaultPublisherGroupOrder); ok {
		if kv.Int != uint64(GroupOrderAscending) && kv.Int != uint64(GroupOrderDescending) {
			return info, protocolViolation("default publisher group order %d", kv.Int)
		}
		info.GroupOrder = GroupOrder(kv.Int)
	}
	if kv, ok := props.Lookup(PropDynamicGroups); ok {
		if kv.Int > 1 {
			return info, protocolViolation("dynamic groups value %d", kv.Int)
		}
		info.DynamicGroups = kv.Int == 1
	}
	return info, nil
}
