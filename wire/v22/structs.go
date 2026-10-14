package v22

import (
	"cmp"
	"io"
	"slices"
	"strings"
)

// Decoder reads fields from a length-bounded buffer. The first failure is
// sticky: later reads return zero values and Err reports the failure.
type Decoder struct {
	b   []byte
	err error
}

func NewDecoder(b []byte) *Decoder { return &Decoder{b: b} }

func (d *Decoder) Err() error { return d.err }

// Len reports the number of unread bytes.
func (d *Decoder) Len() int { return len(d.b) }

func (d *Decoder) fail(err error) {
	if d.err == nil {
		d.err = err
	}
	d.b = nil
}

func (d *Decoder) Varint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n, err := ParseVarint(d.b)
	if err != nil {
		d.fail(err)
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *Decoder) Byte() byte {
	if d.err != nil {
		return 0
	}
	if len(d.b) == 0 {
		d.fail(io.ErrUnexpectedEOF)
		return 0
	}
	c := d.b[0]
	d.b = d.b[1:]
	return c
}

// Bytes returns the next n bytes without copying.
func (d *Decoder) Bytes(n uint64) []byte {
	if d.err != nil {
		return nil
	}
	if n > uint64(len(d.b)) {
		d.fail(io.ErrUnexpectedEOF)
		return nil
	}
	v := d.b[:n:n]
	d.b = d.b[n:]
	return v
}

// LengthPrefixed reads a varint length followed by that many bytes,
// failing with a protocol violation if the length exceeds max.
func (d *Decoder) LengthPrefixed(max uint64, what string) []byte {
	n := d.Varint()
	if d.err == nil && n > max {
		d.fail(protocolViolation("%s length %d exceeds %d", what, n, max))
		return nil
	}
	return d.Bytes(n)
}

// Rest returns all unread bytes.
func (d *Decoder) Rest() []byte {
	if d.err != nil {
		return nil
	}
	v := d.b
	d.b = nil
	return v
}

func appendLengthPrefixed(b, v []byte) []byte {
	return append(AppendVarint(b, uint64(len(v))), v...)
}

// Location identifies an Object within a Track (Section 8.2).
type Location struct {
	Group, Object uint64
}

func (l Location) Compare(o Location) int {
	if c := cmp.Compare(l.Group, o.Group); c != 0 {
		return c
	}
	return cmp.Compare(l.Object, o.Object)
}

func (l Location) Append(b []byte) []byte {
	return AppendVarint(AppendVarint(b, l.Group), l.Object)
}

func (d *Decoder) Location() Location {
	return Location{Group: d.Varint(), Object: d.Varint()}
}

// Limits from Section 8.7.
const (
	MaxNamespaceFields    = 32
	MaxFullTrackNameBytes = 4096
	MaxReasonPhraseBytes  = 1024
	MaxKeyValueBytes      = 1<<16 - 1
)

// Namespace is a Track Namespace tuple. Fields are binary; Go strings are
// used so namespaces can be compared and used as map keys.
type Namespace []string

func (ns Namespace) byteLen() int {
	n := 0
	for _, f := range ns {
		n += len(f)
	}
	return n
}

// Validate applies the limits of Section 8.7.
func (ns Namespace) Validate() error {
	if len(ns) > MaxNamespaceFields {
		return protocolViolation("namespace has %d fields", len(ns))
	}
	for _, f := range ns {
		if f == "" {
			return protocolViolation("empty namespace field")
		}
	}
	if ns.byteLen() > MaxFullTrackNameBytes {
		return protocolViolation("namespace exceeds %d bytes", MaxFullTrackNameBytes)
	}
	return nil
}

// HasPrefix reports whether p is a field-wise prefix of ns (Section 2.4.2).
func (ns Namespace) HasPrefix(p Namespace) bool {
	return len(p) <= len(ns) && slices.Equal(ns[:len(p)], p)
}

// Key returns a string usable as a map key; distinct namespaces never
// collide because each field is length-prefixed.
func (ns Namespace) Key() string {
	var b []byte
	for _, f := range ns {
		b = appendLengthPrefixed(b, []byte(f))
	}
	return string(b)
}

// String renders the namespace in the format recommended by Section 8.8.
func (ns Namespace) String() string {
	parts := make([]string, len(ns))
	for i, f := range ns {
		parts[i] = RenderName(f)
	}
	return strings.Join(parts, "-")
}

func (ns Namespace) Append(b []byte) []byte {
	b = AppendVarint(b, uint64(len(ns)))
	for _, f := range ns {
		b = appendLengthPrefixed(b, []byte(f))
	}
	return b
}

func (d *Decoder) Namespace() Namespace {
	n := d.Varint()
	if d.err == nil && n > MaxNamespaceFields {
		d.fail(protocolViolation("namespace has %d fields", n))
	}
	if d.err != nil {
		return nil
	}
	ns := make(Namespace, n)
	for i := range ns {
		ns[i] = string(d.LengthPrefixed(MaxFullTrackNameBytes, "namespace field"))
	}
	if d.err != nil {
		return nil
	}
	if err := ns.Validate(); err != nil {
		d.fail(err)
		return nil
	}
	return ns
}

// FullTrackName is a namespace plus track name.
type FullTrackName struct {
	Namespace Namespace
	Name      string
}

func (t FullTrackName) Validate() error {
	if err := t.Namespace.Validate(); err != nil {
		return err
	}
	if t.Namespace.byteLen()+len(t.Name) > MaxFullTrackNameBytes {
		return protocolViolation("full track name exceeds %d bytes", MaxFullTrackNameBytes)
	}
	return nil
}

func (t FullTrackName) String() string {
	return t.Namespace.String() + "--" + RenderName(t.Name)
}

func (t FullTrackName) Key() string {
	return t.Namespace.Key() + string(appendLengthPrefixed(nil, []byte(t.Name)))
}

func (t FullTrackName) Append(b []byte) []byte {
	return appendLengthPrefixed(t.Namespace.Append(b), []byte(t.Name))
}

func (d *Decoder) FullTrackName() FullTrackName {
	t := FullTrackName{Namespace: d.Namespace()}
	t.Name = string(d.LengthPrefixed(MaxFullTrackNameBytes, "track name"))
	if d.err == nil {
		if err := t.Validate(); err != nil {
			d.fail(err)
		}
	}
	return t
}

// RenderName renders one binary name component per Section 8.8:
// [a-zA-Z0-9_] verbatim, every other byte as '.' plus two lowercase hex digits.
func RenderName(s string) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		}
	}
	return b.String()
}

func AppendReasonPhrase(b []byte, reason string) []byte {
	if len(reason) > MaxReasonPhraseBytes {
		reason = reason[:MaxReasonPhraseBytes]
	}
	return appendLengthPrefixed(b, []byte(reason))
}

func (d *Decoder) ReasonPhrase() string {
	return string(d.LengthPrefixed(MaxReasonPhraseBytes, "reason phrase"))
}

// KeyValue is one Key-Value-Pair (Section 8.3). Even types carry Int, odd
// types carry Bytes.
type KeyValue struct {
	Type  uint64
	Int   uint64
	Bytes []byte
}

// KeyValues is a list of Key-Value-Pairs. Encoding sorts it by type, since
// types are delta-encoded and so must be non-decreasing on the wire.
type KeyValues []KeyValue

func (kvs KeyValues) Append(b []byte) []byte {
	sorted := slices.SortedStableFunc(slices.Values(kvs), func(a, b KeyValue) int { return cmp.Compare(a.Type, b.Type) })
	var prev uint64
	for _, kv := range sorted {
		b = AppendVarint(b, kv.Type-prev)
		prev = kv.Type
		if kv.Type%2 == 0 {
			b = AppendVarint(b, kv.Int)
		} else {
			b = appendLengthPrefixed(b, kv.Bytes)
		}
	}
	return b
}

// KeyValues decodes Key-Value-Pairs until the decoder is exhausted; callers
// bound it with a sub-decoder of the right length.
func (d *Decoder) KeyValues() KeyValues {
	var kvs KeyValues
	var typ uint64
	for d.err == nil && d.Len() > 0 {
		delta := d.Varint()
		if d.err != nil {
			break
		}
		if delta > MaxVarint-typ {
			d.fail(protocolViolation("key-value type overflow"))
			break
		}
		typ += delta
		kv := KeyValue{Type: typ}
		if typ%2 == 0 {
			kv.Int = d.Varint()
		} else {
			kv.Bytes = d.LengthPrefixed(MaxKeyValueBytes, "key-value")
		}
		kvs = append(kvs, kv)
	}
	return kvs
}

// Get returns the first pair of the given type.
func (kvs KeyValues) Get(typ uint64) (KeyValue, bool) {
	for _, kv := range kvs {
		if kv.Type == typ {
			return kv, true
		}
	}
	return KeyValue{}, false
}

// Sub returns a decoder over the next n bytes and advances past them.
func (d *Decoder) Sub(n uint64) *Decoder {
	b := d.Bytes(n)
	if d.err != nil {
		return &Decoder{err: d.err}
	}
	return NewDecoder(b)
}

// Token alias types (Section 8.9).
type AliasType uint64

const (
	AliasDelete   AliasType = 0x0
	AliasRegister AliasType = 0x1
	AliasUseAlias AliasType = 0x2
	AliasUseValue AliasType = 0x3
)

// Token is the Authorization Token structure (Section 8.9).
type Token struct {
	AliasType AliasType
	Alias     uint64 // DELETE, REGISTER, USE_ALIAS
	Type      uint64 // REGISTER, USE_VALUE
	Value     []byte // REGISTER, USE_VALUE
}

func (t Token) hasAlias() bool { return t.AliasType != AliasUseValue }
func (t Token) hasValue() bool { return t.AliasType == AliasRegister || t.AliasType == AliasUseValue }

func (t Token) Append(b []byte) []byte {
	b = AppendVarint(b, uint64(t.AliasType))
	if t.hasAlias() {
		b = AppendVarint(b, t.Alias)
	}
	if t.hasValue() {
		b = AppendVarint(b, t.Type)
		b = append(b, t.Value...)
	}
	return b
}

// ParseToken decodes a Token from a whole parameter value.
func ParseToken(v []byte) (Token, error) {
	d := NewDecoder(v)
	t := Token{AliasType: AliasType(d.Varint())}
	if d.Err() == nil && t.AliasType > AliasUseValue {
		return Token{}, kvFormattingError("unknown token alias type %d", t.AliasType)
	}
	if t.hasAlias() {
		t.Alias = d.Varint()
	}
	if t.hasValue() {
		t.Type = d.Varint()
		t.Value = d.Rest()
	} else if d.Len() > 0 {
		return Token{}, kvFormattingError("trailing bytes in token")
	}
	if d.Err() != nil {
		return Token{}, kvFormattingError("malformed token: %v", d.Err())
	}
	return t, nil
}
