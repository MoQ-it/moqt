package moqt_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/MoQ-it/moqt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
)

type fetcher struct {
	moqt.RejectAll
	fetch func(*moqt.FetchRequest)
}

func (f *fetcher) HandleFetch(r *moqt.FetchRequest) { f.fetch(r) }

func readFetch(t *testing.T, ctx context.Context, f *moqt.IncomingFetch) []*v22.FetchObject {
	t.Helper()
	var got []*v22.FetchObject
	for {
		o, err := f.Next(ctx)
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatalf("after %d entries: %v", len(got), err)
		}
		got = append(got, o)
	}
}

func TestFetchObjectsAndRanges(t *testing.T) {
	ts := v22.KeyValues{{Type: 0x10, Int: 1234}}
	want := []*v22.FetchObject{
		{Group: 4, Object: 0, Priority: 128, Properties: ts, Payload: []byte("g4-o0")},
		{Group: 4, Object: 1, Priority: 128, Payload: []byte("g4-o1")},
		{Range: v22.FetchRangeNonExistent, Group: 6, Object: 0},
		{Group: 7, Object: 0, SubgroupID: 3, Priority: 7, Payload: []byte("g7-o0")},
		{Group: 7, Object: 5, SubgroupID: 3, Priority: 7, Payload: []byte("g7-o5")},
	}
	reqs := make(chan *moqt.FetchRequest, 1)
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &fetcher{fetch: func(r *moqt.FetchRequest) {
		reqs <- r
		w, err := r.Accept(moqt.FetchAcceptOptions{EndLocation: v22.Location{Group: 7, Object: 5}})
		if err != nil {
			t.Error(err)
			return
		}
		for _, o := range want {
			if err := w.WriteObject(o); err != nil {
				t.Error(err)
				return
			}
		}
		w.Close()
	}}})
	ctx := ctxT(t)
	filter := &v22.LocationFilter{Type: v22.FilterAbsoluteRange, StartGroup: 4, EndGroupDelta: 3}
	f, err := client.Fetch(ctx, track, &v22.Params{LocationFilter: filter})
	if err != nil {
		t.Fatal(err)
	}
	if f.EndLocation != (v22.Location{Group: 7, Object: 5}) || f.EndOfTrack {
		t.Errorf("FETCH_OK end %+v, end of track %v", f.EndLocation, f.EndOfTrack)
	}
	r := <-reqs
	if !reflect.DeepEqual(r.Params.LocationFilter, filter) || !reflect.DeepEqual(r.Track, track) {
		t.Errorf("request %+v %+v", r.Track, r.Params.LocationFilter)
	}
	got := readFetch(t, ctx, f)
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if fmt.Sprint(got[i]) != fmt.Sprint(want[i]) {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestFetchDescending(t *testing.T) {
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &fetcher{fetch: func(r *moqt.FetchRequest) {
		w, err := r.Accept(moqt.FetchAcceptOptions{EndLocation: v22.Location{Group: 3}})
		if err != nil {
			t.Error(err)
			return
		}
		if w.Order != v22.GroupOrderDescending {
			t.Errorf("order %v", w.Order)
		}
		for g := uint64(3); g >= 1; g-- {
			w.WriteObject(&v22.FetchObject{Group: g, Payload: []byte{byte(g)}})
		}
		w.Close()
	}}})
	ctx := ctxT(t)
	f, err := client.Fetch(ctx, track, &v22.Params{GroupOrder: new(v22.GroupOrderDescending)})
	if err != nil {
		t.Fatal(err)
	}
	got := readFetch(t, ctx, f)
	if len(got) != 3 || got[0].Group != 3 || got[2].Group != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestFetchEmpty(t *testing.T) {
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &fetcher{fetch: func(r *moqt.FetchRequest) {
		w, err := r.Accept(moqt.FetchAcceptOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		w.Close()
	}}})
	ctx := ctxT(t)
	f, err := client.Fetch(ctx, track, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFetch(t, ctx, f); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestFetchRejected(t *testing.T) {
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &fetcher{fetch: func(r *moqt.FetchRequest) {
		r.Reject(v22.ReqErrInvalidRange, "too old")
	}}})
	_, err := client.Fetch(ctxT(t), track, nil)
	var re *moqt.RequestError
	if !errors.As(err, &re) || re.Code != v22.ReqErrInvalidRange || re.Reason != "too old" {
		t.Fatalf("got %v; want INVALID_RANGE", err)
	}

	// A Handler without HandleFetch answers NOT_SUPPORTED.
	plain, _ := pair(t, moqt.Config{}, moqt.Config{})
	_, err = plain.Fetch(ctxT(t), track, nil)
	if !errors.As(err, &re) || re.Code != v22.ReqErrNotSupported {
		t.Fatalf("got %v; want NOT_SUPPORTED", err)
	}
}

func TestFetchCancel(t *testing.T) {
	responders := make(chan *moqt.FetchResponder, 1)
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &fetcher{fetch: func(r *moqt.FetchRequest) {
		w, err := r.Accept(moqt.FetchAcceptOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		w.WriteObject(&v22.FetchObject{Payload: []byte("first")})
		responders <- w
	}}})
	ctx := ctxT(t)
	f, err := client.Fetch(ctx, track, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o, err := f.Next(ctx); err != nil || string(o.Payload) != "first" {
		t.Fatalf("first entry %v, %v", o, err)
	}
	w := <-responders
	f.Cancel()
	select {
	case <-w.Context().Done():
	case <-ctx.Done():
		t.Fatal("responder not cancelled")
	}
	if _, err := f.Next(ctx); !errors.Is(err, moqt.ErrFetchCancelled) {
		t.Errorf("Next after Cancel: %v", err)
	}
}

func TestFetchNextContext(t *testing.T) {
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &fetcher{fetch: func(r *moqt.FetchRequest) {
		r.Accept(moqt.FetchAcceptOptions{}) // never writes
	}}})
	f, err := client.Fetch(ctxT(t), track, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v", err)
	}
}
