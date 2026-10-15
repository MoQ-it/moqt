package v22

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
)

type dataGolden struct {
	SubgroupStreams []struct{ Name, Hex string } `json:"subgroupStreams"`
	Datagrams       []struct{ Name, Hex string } `json:"datagrams"`
	FetchStreams    []struct{ Name, Hex string } `json:"fetchStreams"`
}

func loadDataGolden(t *testing.T) dataGolden {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/v22/data.json")
	if err != nil {
		t.Fatal(err)
	}
	var g dataGolden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSubgroupGolden(t *testing.T) {
	g := loadDataGolden(t)
	hdr := &SubgroupHeader{TrackAlias: 1, Group: 5, IDMode: SubgroupIDZero, HasPriority: true, Priority: 16}
	objs := []*Object{{ID: 0, Payload: []byte("a")}, {ID: 1, Payload: []byte("bc")}, {ID: 3, Status: StatusEndOfGroup}}

	w := &SubgroupWriter{Header: hdr}
	b := hdr.Append(nil)
	for _, o := range objs {
		var err error
		if b, err = w.AppendObject(b, o); err != nil {
			t.Fatal(err)
		}
	}
	if got := hex.EncodeToString(b); got != g.SubgroupStreams[0].Hex {
		t.Fatalf("encoded %s\nwant    %s", got, g.SubgroupStreams[0].Hex)
	}

	r := bufio.NewReader(bytes.NewReader(mustHex(t, g.SubgroupStreams[0].Hex)))
	typ, err := ReadVarint(r)
	if err != nil {
		t.Fatal(err)
	}
	gotHdr, err := ReadSubgroupHeader(r, typ)
	if err != nil || !reflect.DeepEqual(gotHdr, hdr) {
		t.Fatalf("header %+v, %v; want %+v", gotHdr, err, hdr)
	}
	sr := NewSubgroupReader(r, gotHdr)
	for _, want := range objs {
		got, err := sr.Next()
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("object %+v, %v; want %+v", got, err, want)
		}
	}
	if _, err := sr.Next(); err != io.EOF {
		t.Fatalf("end of stream: %v; want io.EOF", err)
	}
}

func TestFetchGolden(t *testing.T) {
	g := loadDataGolden(t)
	entries := []*FetchObject{
		{Group: 5, Object: 0, Priority: 16, Payload: []byte("a")},
		{Group: 5, Object: 1, Priority: 16, Payload: []byte("bc")},
		{Range: FetchRangeNonExistent, Group: 7, Object: 0},
		{Group: 8, Object: 2, SubgroupID: 1, Priority: 16, Payload: []byte("z")},
		{Group: 8, Object: 3, Datagram: true, Priority: 32},
	}
	w := NewFetchWriter(GroupOrderAscending)
	b := FetchHeader{RequestID: 3}.Append(nil)
	for _, o := range entries {
		var err error
		if b, err = w.Append(b, o); err != nil {
			t.Fatal(err)
		}
	}
	if got := hex.EncodeToString(b); got != g.FetchStreams[0].Hex {
		t.Fatalf("encoded %s\nwant    %s", got, g.FetchStreams[0].Hex)
	}

	r := bufio.NewReader(bytes.NewReader(mustHex(t, g.FetchStreams[0].Hex)))
	if typ, err := ReadVarint(r); err != nil || typ != StreamTypeFetch {
		t.Fatalf("stream type %x, %v", typ, err)
	}
	if id, err := ReadVarint(r); err != nil || id != 3 {
		t.Fatalf("request ID %d, %v", id, err)
	}
	fr := NewFetchReader(r, GroupOrderAscending)
	for _, want := range entries {
		got, err := fr.Next()
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("entry %+v, %v; want %+v", got, err, want)
		}
	}
	if _, err := fr.Next(); err != io.EOF {
		t.Fatalf("end of stream: %v; want io.EOF", err)
	}
}

func TestSubgroupVariants(t *testing.T) {
	for _, hdr := range []*SubgroupHeader{
		{TrackAlias: 9, Group: 1 << 40, IDMode: SubgroupIDExplicit, SubgroupID: 7, Properties: true, EndOfGroup: true, FirstObject: true},
		{TrackAlias: 0, Group: 0, IDMode: SubgroupIDFirstObject, HasPriority: true, Priority: 255},
	} {
		objs := []*Object{
			{ID: 10, Payload: bytes.Repeat([]byte{1}, 3000)},
			{ID: 11, Status: StatusNormal}, // empty Normal object
			{ID: 20, Payload: []byte("x")},
		}
		if hdr.Properties {
			objs[0].Properties = KeyValues{{Type: 0x0C, Int: 42}}
			objs[2].Properties = KeyValues{{Type: 0x3801, Bytes: []byte("app")}}
		}
		w := &SubgroupWriter{Header: hdr}
		b := hdr.Append(nil)
		for _, o := range objs {
			var err error
			if b, err = w.AppendObject(b, o); err != nil {
				t.Fatal(err)
			}
		}
		r := bufio.NewReader(bytes.NewReader(b))
		typ, _ := ReadVarint(r)
		gotHdr, err := ReadSubgroupHeader(r, typ)
		if err != nil || !reflect.DeepEqual(gotHdr, hdr) {
			t.Fatalf("header %+v, %v; want %+v", gotHdr, err, hdr)
		}
		sr := NewSubgroupReader(r, gotHdr)
		for _, want := range objs {
			got, err := sr.Next()
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != want.ID || !bytes.Equal(got.Payload, want.Payload) || got.Status != want.Status || len(got.Properties) != len(want.Properties) {
				t.Fatalf("object %+v; want %+v", got, want)
			}
		}
	}
}

func TestSubgroupViolations(t *testing.T) {
	for _, typ := range []uint64{0x00, 0x0F, 0x16 /* mode 0b11 */, 0x80} {
		if _, err := ReadSubgroupHeader(bufio.NewReader(bytes.NewReader([]byte{1, 1})), typ); err == nil {
			t.Errorf("type 0x%x accepted", typ)
		}
	}
	// FIN in the middle of an object's payload.
	hdr := &SubgroupHeader{TrackAlias: 1, Group: 1}
	b, _ := (&SubgroupWriter{Header: hdr}).AppendObject(nil, &Object{ID: 0, Payload: []byte("hello")})
	sr := NewSubgroupReader(bufio.NewReader(bytes.NewReader(b[:len(b)-2])), hdr)
	_, err := sr.Next()
	wantViolation(t, "FIN mid-object", err)

	// Status values other than 0, 3, 4.
	sr = NewSubgroupReader(bufio.NewReader(bytes.NewReader([]byte{0x00, 0x00, 0x01})), hdr)
	_, err = sr.Next()
	wantViolation(t, "bad status", err)

	if _, err := (&SubgroupWriter{Header: hdr}).AppendObject(nil, &Object{ID: 0, Status: StatusEndOfTrack, Payload: []byte("x")}); err == nil {
		t.Error("End of Track object with a payload must not encode")
	}
}

func TestDatagramGolden(t *testing.T) {
	g := loadDataGolden(t)
	want := []*Datagram{
		{TrackAlias: 2, Group: 7, Object: 0, Payload: []byte("hi")},
		{TrackAlias: 2, Group: 7, Object: 4, HasPriority: true, Priority: 32, Status: StatusEndOfGroup},
	}
	for i, v := range g.Datagrams {
		b, err := AppendDatagram(nil, want[i])
		if err != nil || hex.EncodeToString(b) != v.Hex {
			t.Errorf("%s: encoded %x, %v; want %s", v.Name, b, err, v.Hex)
		}
		got, err := ParseDatagram(mustHex(t, v.Hex))
		if err != nil || !reflect.DeepEqual(got, want[i]) {
			t.Errorf("%s: parsed %+v, %v", v.Name, got, err)
		}
	}
}

func TestDatagramVariants(t *testing.T) {
	for _, d := range []*Datagram{
		{TrackAlias: 1 << 30, Group: 3, Object: 99, HasPriority: true, Priority: 1, Properties: KeyValues{{Type: 0x0C, Int: 30}}, EndOfGroup: true, Payload: []byte("opus")},
		{TrackAlias: 1, Group: 1, Object: 1, Status: StatusEndOfTrack},
		{TrackAlias: 1, Group: 1, Object: 2, Properties: KeyValues{{Type: 0x0C, Int: 0}}, Status: StatusNormal}, // empty Normal with properties
	} {
		b, err := AppendDatagram(nil, d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseDatagram(b)
		if err != nil || !reflect.DeepEqual(got, d) {
			t.Fatalf("parsed %+v, %v; want %+v", got, err, d)
		}
	}
	for name, b := range map[string][]byte{
		"reserved bit":          {0x10, 1, 1},
		"status+end of group":   {0x22, 1, 1, 1, 0},
		"unknown bit":           {0x40, 1, 1},
		"empty properties":      {0x01 | 0x04 | 0x08, 1, 1, 0x00},
		"truncated":             {0x00, 1},
		"bytes after status":    {0x20 | 0x04 | 0x08, 1, 1, 0x00, 0x01},
		"props on end of group": {0x20 | 0x01 | 0x04 | 0x08, 1, 1, 0x02, 0x0C, 0x01, 0x03},
	} {
		_, err := ParseDatagram(b)
		wantViolation(t, name, err)
	}
	if _, err := ParseDatagram(AppendVarint(nil, DatagramPadding)); !errors.Is(err, ErrPaddingDatagram) {
		t.Errorf("padding: %v", err)
	}
}

func TestFetchRoundTrip(t *testing.T) {
	for _, order := range []GroupOrder{GroupOrderAscending, GroupOrderDescending} {
		entries := []*FetchObject{
			{Group: 10, Object: 0, SubgroupID: 0, Priority: 64, Payload: []byte("k")},
			{Group: 10, Object: 1, SubgroupID: 0, Priority: 64, Payload: []byte("d1")},
			{Group: 10, Object: 5, SubgroupID: 1, Priority: 64, Payload: []byte("d5")},
			{Range: FetchRangeNonExistent, Group: 10, Object: 9},
			{Group: 10, Object: 10, SubgroupID: 2, Priority: 70, Properties: KeyValues{{Type: 0x0C, Int: 5}}},
			{Group: 10, Object: 11, Datagram: true, Priority: 70, Payload: []byte("dg")},
			{Group: 10, Object: 12, SubgroupID: 9, Priority: 70, Payload: []byte("e")},
		}
		next := []*FetchObject{
			{Group: 13, Object: 0, SubgroupID: 9, Priority: 70, Payload: []byte("k2")},
			{Range: FetchRangeTimedOut, Group: 14, Object: 3},
			{Group: 15, Object: 0, SubgroupID: 0, Priority: 1, Payload: []byte("k3")},
		}
		if order == GroupOrderDescending {
			for _, e := range next {
				e.Group = 20 - e.Group // 7, 6, 5: descending after group 10
			}
		}
		entries = append(entries, next...)

		w := NewFetchWriter(order)
		b := FetchHeader{RequestID: 8}.Append(nil)
		for _, e := range entries {
			var err error
			if b, err = w.Append(b, e); err != nil {
				t.Fatalf("order %d: encode %+v: %v", order, e, err)
			}
		}
		r := bufio.NewReader(bytes.NewReader(b))
		if typ, _ := ReadVarint(r); typ != StreamTypeFetch {
			t.Fatalf("stream type %d", typ)
		}
		if id, _ := ReadVarint(r); id != 8 {
			t.Fatalf("request id %d", id)
		}
		fr := NewFetchReader(r, order)
		for _, want := range entries {
			got, err := fr.Next()
			if err != nil {
				t.Fatalf("order %d: decode: %v", order, err)
			}
			if got.Range != want.Range || got.Group != want.Group || got.Object != want.Object ||
				(want.Range == 0 && (got.Datagram != want.Datagram || (!want.Datagram && got.SubgroupID != want.SubgroupID) ||
					got.Priority != want.Priority || !bytes.Equal(got.Payload, want.Payload) || len(got.Properties) != len(want.Properties))) {
				t.Fatalf("order %d: got %+v; want %+v", order, got, want)
			}
		}
		if _, err := fr.Next(); err != io.EOF {
			t.Fatalf("end: %v", err)
		}
	}
}

func TestFetchViolations(t *testing.T) {
	// First entry without group/object deltas.
	fr := NewFetchReader(bufio.NewReader(bytes.NewReader([]byte{0x10, 0x01, 0x00})), GroupOrderAscending)
	_, err := fr.Next()
	wantViolation(t, "first entry relative", err)

	// First entry referencing the prior subgroup.
	fr = NewFetchReader(bufio.NewReader(bytes.NewReader([]byte{0x1D, 0x00, 0x00, 0x01, 0x00})), GroupOrderAscending)
	_, err = fr.Next()
	wantViolation(t, "prior subgroup", err)

	// Reserved serialization flags.
	fr = NewFetchReader(bufio.NewReader(bytes.NewReader(AppendVarint(nil, 0x90))), GroupOrderAscending)
	_, err = fr.Next()
	wantViolation(t, "reserved flags", err)
}
