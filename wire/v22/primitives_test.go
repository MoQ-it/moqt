package v22

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"testing"
)

type golden struct {
	Varints []struct {
		Hex     string `json:"hex"`
		Value   string `json:"value"`
		Minimal bool   `json:"minimal"`
	} `json:"varints"`
	KeyValues []struct {
		Hex   string `json:"hex"`
		Pairs []struct {
			Type     string `json:"type"`
			Int      string `json:"int"`
			BytesHex string `json:"bytesHex"`
		} `json:"pairs"`
	} `json:"keyValues"`
	Namespaces []struct {
		Hex      string   `json:"hex"`
		Fields   []string `json:"fields"`
		Rendered string   `json:"rendered"`
	} `json:"namespaces"`
	RenderedNames []struct {
		Namespace []string `json:"namespace"`
		Track     string   `json:"track"`
		Rendered  string   `json:"rendered"`
	} `json:"renderedNames"`
	Tokens []struct {
		Hex       string `json:"hex"`
		AliasType uint64 `json:"aliasType"`
		Alias     string `json:"alias"`
		Type      string `json:"type"`
		ValueHex  string `json:"valueHex"`
	} `json:"tokens"`
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	b, err := os.ReadFile("../../testdata/v22/primitives.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustUint(t *testing.T, s string) uint64 {
	t.Helper()
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVarintGolden(t *testing.T) {
	for _, v := range loadGolden(t).Varints {
		enc := mustHex(t, v.Hex)
		want := mustUint(t, v.Value)

		got, n, err := ParseVarint(enc)
		if err != nil || got != want || n != len(enc) {
			t.Errorf("ParseVarint(%s) = %d, %d, %v; want %d, %d", v.Hex, got, n, err, want, len(enc))
		}
		got, err = ReadVarint(bufio.NewReader(bytes.NewReader(enc)))
		if err != nil || got != want {
			t.Errorf("ReadVarint(%s) = %d, %v; want %d", v.Hex, got, err, want)
		}
		if v.Minimal {
			if b := AppendVarint(nil, want); !bytes.Equal(b, enc) {
				t.Errorf("AppendVarint(%d) = %x; want %s", want, b, v.Hex)
			}
			if VarintLen(want) != len(enc) {
				t.Errorf("VarintLen(%d) = %d; want %d", want, VarintLen(want), len(enc))
			}
		}
	}
}

func TestVarintRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 100000 {
		v := r.Uint64() >> r.UintN(64)
		b := AppendVarint(nil, v)
		got, n, err := ParseVarint(b)
		if err != nil || got != v || n != len(b) {
			t.Fatalf("round trip %d: got %d, %d, %v (enc %x)", v, got, n, err, b)
		}
	}
}

func TestVarintTruncated(t *testing.T) {
	for _, enc := range [][]byte{{}, {0x80}, {0xff, 1, 2, 3}, {0xfe, 0, 0, 0, 0, 0, 0}} {
		if _, _, err := ParseVarint(enc); err == nil {
			t.Errorf("ParseVarint(%x) succeeded on truncated input", enc)
		}
		if _, err := ReadVarint(bufio.NewReader(bytes.NewReader(enc))); err == nil {
			t.Errorf("ReadVarint(%x) succeeded on truncated input", enc)
		}
	}
}

func TestKeyValuesGolden(t *testing.T) {
	for _, g := range loadGolden(t).KeyValues {
		var kvs KeyValues
		for _, p := range g.Pairs {
			kvs = append(kvs, KeyValue{Type: mustUint(t, p.Type), Int: mustUint(t, p.Int), Bytes: mustHex(t, p.BytesHex)})
		}
		// Encoding must sort by type regardless of input order, keeping the
		// relative order of pairs that share a type.
		shuffled := append(slices.Clone(kvs[len(kvs)-1:]), kvs[:len(kvs)-1]...)
		if b := shuffled.Append(nil); hex.EncodeToString(b) != g.Hex {
			t.Errorf("KeyValues.Append = %x; want %s", b, g.Hex)
		}
		d := NewDecoder(mustHex(t, g.Hex))
		got := d.KeyValues()
		if d.Err() != nil || len(got) != len(kvs) {
			t.Fatalf("decode: %v, %d pairs", d.Err(), len(got))
		}
		for i := range kvs {
			if got[i].Type != kvs[i].Type || got[i].Int != kvs[i].Int || !bytes.Equal(got[i].Bytes, kvs[i].Bytes) {
				t.Errorf("pair %d = %+v; want %+v", i, got[i], kvs[i])
			}
		}
	}
}

func TestKeyValueTooLong(t *testing.T) {
	b := AppendVarint([]byte{0x01}, MaxKeyValueBytes+1)
	d := NewDecoder(b)
	d.KeyValues()
	var se *SessionError
	if !errors.As(d.Err(), &se) || se.Code != ErrProtocolViolation {
		t.Fatalf("got %v; want protocol violation", d.Err())
	}
}

func TestNamespaceGolden(t *testing.T) {
	g := loadGolden(t)
	for _, n := range g.Namespaces {
		ns := Namespace(n.Fields)
		if b := ns.Append(nil); hex.EncodeToString(b) != n.Hex {
			t.Errorf("Namespace.Append = %x; want %s", b, n.Hex)
		}
		d := NewDecoder(mustHex(t, n.Hex))
		if got := d.Namespace(); d.Err() != nil || !slices.Equal(got, ns) {
			t.Errorf("decode = %q, %v", got, d.Err())
		}
		if ns.String() != n.Rendered {
			t.Errorf("String = %q; want %q", ns.String(), n.Rendered)
		}
	}
	for _, r := range g.RenderedNames {
		if s := (FullTrackName{Namespace: r.Namespace, Name: r.Track}).String(); s != r.Rendered {
			t.Errorf("rendered %q; want %q", s, r.Rendered)
		}
	}
}

func TestNamespaceLimits(t *testing.T) {
	tooMany := make(Namespace, MaxNamespaceFields+1)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	for name, ns := range map[string]Namespace{
		"empty field": {"a", ""},
		"too many":    tooMany,
		"too long":    {string(make([]byte, MaxFullTrackNameBytes+1))},
	} {
		d := NewDecoder(ns.Append(nil))
		d.Namespace()
		var se *SessionError
		if !errors.As(d.Err(), &se) || se.Code != ErrProtocolViolation {
			t.Errorf("%s: got %v; want protocol violation", name, d.Err())
		}
	}
	if !(Namespace{"moqit", "r1", "p"}).HasPrefix(Namespace{"moqit", "r1"}) || (Namespace{"moqit", "r10"}).HasPrefix(Namespace{"moqit", "r1"}) {
		t.Error("HasPrefix must match whole fields")
	}
	if (Namespace{"ab", "c"}).Key() == (Namespace{"a", "bc"}).Key() {
		t.Error("namespace keys collide")
	}
}

func TestTokenGolden(t *testing.T) {
	for _, g := range loadGolden(t).Tokens {
		want := Token{AliasType: AliasType(g.AliasType), Alias: mustUint(t, g.Alias), Type: mustUint(t, g.Type), Value: mustHex(t, g.ValueHex)}
		if b := want.Append(nil); hex.EncodeToString(b) != g.Hex {
			t.Errorf("Token.Append = %x; want %s", b, g.Hex)
		}
		got, err := ParseToken(mustHex(t, g.Hex))
		if err != nil || got.AliasType != want.AliasType || got.Alias != want.Alias || got.Type != want.Type || !bytes.Equal(got.Value, want.Value) {
			t.Errorf("ParseToken(%s) = %+v, %v; want %+v", g.Hex, got, err, want)
		}
	}
	if _, err := ParseToken([]byte{0x02, 0x05, 0x00}); err == nil {
		t.Error("USE_ALIAS with trailing bytes must fail")
	}
}

func TestTrackInfo(t *testing.T) {
	info, err := ParseTrackInfo(nil)
	if err != nil || info.PublisherPriority != 128 || info.GroupOrder != GroupOrderAscending || info.DynamicGroups {
		t.Fatalf("defaults: %+v, %v", info, err)
	}
	imm := KeyValues{{Type: PropDynamicGroups, Int: 1}}.Append(nil)
	info, err = ParseTrackInfo(KeyValues{{Type: PropDefaultPublisherPriority, Int: 16}, {Type: PropImmutable, Bytes: imm}})
	if err != nil || info.PublisherPriority != 16 || !info.DynamicGroups {
		t.Fatalf("explicit: %+v, %v", info, err)
	}
	if _, err := ParseTrackInfo(KeyValues{{Type: PropDynamicGroups, Int: 2}}); err == nil {
		t.Error("DYNAMIC_GROUPS=2 accepted")
	}
}
