package v22

import (
	"bufio"
	"bytes"
	"testing"
)

// The parsers face untrusted peers: they must reject bad input with an
// error, never panic or over-allocate.

func FuzzReadMessage(f *testing.F) {
	f.Add(mustHexF("0300140002056d6f716974027231036d69630220100105"))
	f.Add(mustHexF("af00000f01042f6d6f7106076d6f71742d676f"))
	for _, m := range []Message{
		&Subscribe{RequestID: 2, Track: FullTrackName{Namespace: ns, Name: "x"}, Params: fullParams()},
		&RequestError{Code: ReqErrRedirect, Reason: "r", Redirect: &Redirect{Track: FullTrackName{Namespace: ns, Name: "y"}}},
		&FetchOK{EndLocation: Location{Group: 1}, Params: &Params{}},
	} {
		b, _ := AppendMessage(nil, m)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bufio.NewReader(bytes.NewReader(b))
		for {
			m, err := ReadMessage(r)
			if err != nil {
				return
			}
			// Whatever decodes must re-encode.
			if _, err := AppendMessage(nil, m); err != nil {
				t.Fatalf("decoded %T does not re-encode: %v", m, err)
			}
		}
	})
}

func FuzzParseDatagram(f *testing.F) {
	f.Add(mustHexF("0c02076869"))
	f.Add(mustHexF("200207042003"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseDatagram(b)
	})
}

func FuzzDataStreams(f *testing.F) {
	f.Add(mustHexF("1001051000016100026263010003"))
	f.Add(append(FetchHeader{RequestID: 1}.Append(nil), 0x1C, 0x05, 0x00, 0x40, 0x01, 0x61))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bufio.NewReader(bytes.NewReader(b))
		typ, err := ReadVarint(r)
		if err != nil {
			return
		}
		switch {
		case typ == StreamTypeFetch:
			if _, err := ReadVarint(r); err != nil {
				return
			}
			fr := NewFetchReader(r, GroupOrderAscending)
			for i := 0; i < 1000; i++ {
				if _, err := fr.Next(); err != nil {
					return
				}
			}
		case IsSubgroupStreamType(typ):
			h, err := ReadSubgroupHeader(r, typ)
			if err != nil {
				return
			}
			sr := NewSubgroupReader(r, h)
			for i := 0; i < 1000; i++ {
				if _, err := sr.Next(); err != nil {
					return
				}
			}
		}
	})
}

func mustHexF(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c-'a') + 10
			}
		}
		b[i] = v
	}
	return b
}
