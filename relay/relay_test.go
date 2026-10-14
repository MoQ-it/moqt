package relay_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoQ-it/moqt"
	"github.com/MoQ-it/moqt/relay"
	"github.com/MoQ-it/moqt/transport/rawquic"
	v22 "github.com/MoQ-it/moqt/wire/v22"
	"github.com/quic-go/quic-go"
)

var (
	alice = v22.Namespace{"moqit", "r1", "p", "alice"}
	cam   = v22.FullTrackName{Namespace: alice, Name: "camera-h"}
)

// harness runs a relay on a QUIC listener and connects clients to it.
type harness struct {
	t    *testing.T
	r    *relay.Relay
	addr string
}

func newHarness(t *testing.T, cfg relay.Config) *harness {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	tlsConf := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{v22.ALPN}}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 1000, MaxIncomingUniStreams: 1000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h := &harness{t: t, r: relay.New(cfg), addr: ln.Addr().String()}
	go func() {
		for {
			qc, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				peer := h.r.NewPeer(qc.RemoteAddr().String())
				s, err := moqt.NewSession(context.Background(), rawquic.New(qc), moqt.Server, moqt.Config{Handler: peer})
				if err != nil {
					return
				}
				peer.Attach(s)
			}()
		}
	}()
	return h
}

func (h *harness) connect(handler moqt.Handler) *moqt.Session {
	return h.connectWith(handler, &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 1000, MaxIncomingUniStreams: 1000})
}

func (h *harness) connectWith(handler moqt.Handler, qconf *quic.Config) *moqt.Session {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, h.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{v22.ALPN}}, qconf)
	if err != nil {
		h.t.Fatal(err)
	}
	s, err := moqt.NewSession(ctx, rawquic.New(qc), moqt.Client, moqt.Config{Handler: handler})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { s.Close() })
	return s
}

// publisher is a client that answers the relay's SUBSCRIBEs.
type publisher struct {
	moqt.RejectAll
	subscribes atomic.Int32
	lastParams atomic.Pointer[v22.Params]
	writers    chan *moqt.TrackWriter
	props      v22.KeyValues
}

func newPublisher(props v22.KeyValues) *publisher {
	return &publisher{writers: make(chan *moqt.TrackWriter, 4), props: props}
}

func (p *publisher) HandleSubscribe(r *moqt.SubscribeRequest) {
	p.subscribes.Add(1)
	p.lastParams.Store(r.Params)
	w, err := r.Accept(moqt.AcceptOptions{Properties: p.props})
	if err != nil {
		return
	}
	p.writers <- w
}

func writeGroup(t *testing.T, w *moqt.TrackWriter, group uint64, n int) {
	t.Helper()
	sg := w.OpenSubgroup(group, 0, moqt.SubgroupOptions{EndOfGroup: true})
	for i := range uint64(n) {
		if err := sg.WriteObject(&v22.Object{ID: i, Payload: []byte(fmt.Sprintf("%d/%d", group, i))}); err != nil {
			t.Error(err)
		}
	}
	sg.Close()
}

// readGroup reads one subgroup and returns its payloads.
func readGroup(t *testing.T, ctx context.Context, sub *moqt.Subscription) (uint64, []string) {
	t.Helper()
	g, err := sub.AcceptSubgroup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		o, err := g.Next()
		if err == io.EOF {
			return g.Header.Group, got
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(o.Payload))
	}
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func current() *v22.Params {
	return &v22.Params{LocationFilter: &v22.LocationFilter{Type: v22.FilterRelativeStart, StartGroup: 1}}
}

func TestFanOutSingleUpstream(t *testing.T) {
	h := newHarness(t, relay.Config{})
	ctx := ctxT(t)
	pub := newPublisher(nil)
	ps := h.connect(pub)
	if _, err := ps.PublishNamespace(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}

	subs := make([]*moqt.Subscription, 3)
	for i := range subs {
		sub, err := h.connect(nil).Subscribe(ctx, cam, current())
		if err != nil {
			t.Fatal(err)
		}
		subs[i] = sub
	}
	w := <-pub.writers
	if n := pub.subscribes.Load(); n != 1 {
		t.Fatalf("publisher got %d SUBSCRIBEs; want 1", n)
	}
	if f := pub.lastParams.Load().LocationFilter; f == nil || f.Type != v22.FilterRelativeStart || f.StartGroup != 1 {
		t.Errorf("upstream filter %+v; want relative start 1", f)
	}
	writeGroup(t, w, 7, 4)
	for i, sub := range subs {
		g, got := readGroup(t, ctx, sub)
		if g != 7 || fmt.Sprint(got) != "[7/0 7/1 7/2 7/3]" {
			t.Errorf("subscriber %d: group %d %v", i, g, got)
		}
	}
}

func TestLateJoinerStartsAtCurrentGroup(t *testing.T) {
	h := newHarness(t, relay.Config{})
	ctx := ctxT(t)
	pub := newPublisher(nil)
	ps := h.connect(pub)
	if _, err := ps.PublishNamespace(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}
	first, err := h.connect(nil).Subscribe(ctx, cam, current())
	if err != nil {
		t.Fatal(err)
	}
	w := <-pub.writers
	writeGroup(t, w, 4, 2)
	writeGroup(t, w, 5, 3)
	readGroup(t, ctx, first)
	readGroup(t, ctx, first)

	// Joins after group 5 was sent: served from the relay's cache, from
	// the start of the current group only.
	late, err := h.connect(nil).Subscribe(ctx, cam, current())
	if err != nil {
		t.Fatal(err)
	}
	if late.LargestObject == nil || late.LargestObject.Group != 5 {
		t.Errorf("largest %+v; want group 5", late.LargestObject)
	}
	g, got := readGroup(t, ctx, late)
	if g != 5 || fmt.Sprint(got) != "[5/0 5/1 5/2]" {
		t.Errorf("late joiner got group %d %v; want group 5 from object 0", g, got)
	}
	// And live data afterwards.
	writeGroup(t, w, 6, 1)
	if g, _ := readGroup(t, ctx, late); g != 6 {
		t.Errorf("then group %d; want 6", g)
	}

	// A subscriber with no filter gets only subgroups that start later.
	live, err := h.connect(nil).Subscribe(ctx, cam, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeGroup(t, w, 7, 1)
	if g, _ := readGroup(t, ctx, live); g != 7 {
		t.Errorf("unfiltered subscriber got group %d first; want 7", g)
	}
}

func TestNewGroupRequestForwarded(t *testing.T) {
	h := newHarness(t, relay.Config{})
	ctx := ctxT(t)
	pub := newPublisher(v22.KeyValues{{Type: v22.PropDynamicGroups, Int: 1}})
	ps := h.connect(pub)
	if _, err := ps.PublishNamespace(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}
	sub, err := h.connect(nil).Subscribe(ctx, cam, current())
	if err != nil {
		t.Fatal(err)
	}
	w := <-pub.writers
	writeGroup(t, w, 3, 1)
	readGroup(t, ctx, sub)
	if !sub.Info.DynamicGroups {
		t.Fatal("DYNAMIC_GROUPS property not passed through")
	}
	if err := sub.Update(ctx, &v22.Params{NewGroupRequest: new(uint64(0))}); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-w.Updates():
		if p.NewGroupRequest == nil || *p.NewGroupRequest != 0 {
			t.Errorf("upstream update %+v", p)
		}
	case <-ctx.Done():
		t.Fatal("NEW_GROUP_REQUEST not forwarded upstream")
	}
	// A request for a Group that already exists is not forwarded.
	if err := sub.Update(ctx, &v22.Params{NewGroupRequest: new(uint64(2))}); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-w.Updates():
		t.Errorf("stale NEW_GROUP_REQUEST forwarded: %+v", p)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestUpstreamReleasedAfterLinger(t *testing.T) {
	h := newHarness(t, relay.Config{Linger: 100 * time.Millisecond})
	ctx := ctxT(t)
	pub := newPublisher(nil)
	ps := h.connect(pub)
	if _, err := ps.PublishNamespace(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}
	sub, err := h.connect(nil).Subscribe(ctx, cam, current())
	if err != nil {
		t.Fatal(err)
	}
	w := <-pub.writers
	sub.Unsubscribe()
	select {
	case <-w.Context().Done():
	case <-ctx.Done():
		t.Fatal("upstream not released")
	}
	if n := h.r.TrackCount(); n != 0 {
		t.Errorf("relay still tracks %d tracks", n)
	}
	// Subscribing again creates a new upstream subscription.
	if _, err := h.connect(nil).Subscribe(ctx, cam, current()); err != nil {
		t.Fatal(err)
	}
	<-pub.writers
	if n := pub.subscribes.Load(); n != 2 {
		t.Errorf("publisher got %d SUBSCRIBEs; want 2", n)
	}
}

func TestPublisherDoneEndsSubscribers(t *testing.T) {
	h := newHarness(t, relay.Config{})
	ctx := ctxT(t)
	pub := newPublisher(nil)
	ps := h.connect(pub)
	if _, err := ps.PublishNamespace(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}
	sub, err := h.connect(nil).Subscribe(ctx, cam, current())
	if err != nil {
		t.Fatal(err)
	}
	w := <-pub.writers
	writeGroup(t, w, 1, 2)
	w.Close(v22.DoneTrackEnded, "bye")
	if g, got := readGroup(t, ctx, sub); g != 1 || len(got) != 2 {
		t.Errorf("group %d %v", g, got)
	}
	select {
	case <-sub.Done():
	case <-ctx.Done():
		t.Fatal("subscriber not ended")
	}
	if res, err := sub.Result(); err != nil || res.StatusCode != v22.DoneTrackEnded || res.StreamCount != 1 {
		t.Errorf("result %+v, %v", res, err)
	}
}

func TestUnknownTrackAndAuthorization(t *testing.T) {
	h := newHarness(t, relay.Config{Authorizer: denyScreen{}})
	ctx := ctxT(t)
	_, err := h.connect(nil).Subscribe(ctx, cam, nil)
	var re *moqt.RequestError
	if !errors.As(err, &re) || re.Code != v22.ReqErrDoesNotExist {
		t.Errorf("unknown track: %v; want DOES_NOT_EXIST", err)
	}
	_, err = h.connect(nil).Subscribe(ctx, v22.FullTrackName{Namespace: alice, Name: "screen-h"}, nil)
	if !errors.As(err, &re) || re.Code != v22.ReqErrUnauthorized {
		t.Errorf("denied track: %v; want UNAUTHORIZED", err)
	}
}

type denyScreen struct{}

func (denyScreen) AuthorizePublishNamespace(*relay.Peer, v22.Namespace, *v22.Params) error {
	return nil
}
func (denyScreen) AuthorizeSubscribeNamespace(*relay.Peer, v22.Namespace, *v22.Params) error {
	return nil
}
func (denyScreen) AuthorizeSubscribe(_ *relay.Peer, t v22.FullTrackName, _ *v22.Params) error {
	if t.Name == "screen-h" {
		return errors.New("no screen for you")
	}
	return nil
}

func TestNamespaceDiscovery(t *testing.T) {
	h := newHarness(t, relay.Config{})
	ctx := ctxT(t)
	watcher := h.connect(nil)
	ns, err := watcher.SubscribeNamespace(ctx, v22.Namespace{"moqit", "r1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pn, err := h.connect(newPublisher(nil)).PublishNamespace(ctx, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ns.Next(ctx)
	if err != nil || !e.Active || e.Suffix.String() != "p-alice" {
		t.Fatalf("event %+v, %v", e, err)
	}
	pn.Withdraw()
	e, err = ns.Next(ctx)
	if err != nil || e.Active || e.Suffix.String() != "p-alice" {
		t.Fatalf("event %+v, %v", e, err)
	}
	// A watcher arriving later is told about existing namespaces.
	h.connect(newPublisher(nil)).PublishNamespace(ctx, v22.Namespace{"moqit", "r1", "p", "bob"}, nil)
	ns2, err := h.connect(nil).SubscribeNamespace(ctx, v22.Namespace{"moqit", "r1", "p"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := ns2.Next(ctx); err != nil || e.Suffix.String() != "bob" {
		t.Fatalf("late watcher event %+v, %v", e, err)
	}
}

func TestDeliveryTimeoutSkipsStaleGroups(t *testing.T) {
	h := newHarness(t, relay.Config{DeliveryTimeout: 300 * time.Millisecond})
	ctx := ctxT(t)
	pub := newPublisher(nil)
	if _, err := h.connect(pub).PublishNamespace(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}
	// A congested subscriber: each stream can hold only 4 KB in flight.
	slow := h.connectWith(nil, &quic.Config{
		EnableDatagrams: true, MaxIncomingUniStreams: 1000,
		InitialStreamReceiveWindow: 4096, MaxStreamReceiveWindow: 4096,
		InitialConnectionReceiveWindow: 1 << 24, MaxConnectionReceiveWindow: 1 << 24,
	})
	sub, err := slow.Subscribe(ctx, cam, current())
	if err != nil {
		t.Fatal(err)
	}
	w := <-pub.writers

	// Group 0 is far bigger than the subscriber's stream window.
	big := w.OpenSubgroup(0, 0, moqt.SubgroupOptions{})
	for i := range uint64(20) {
		big.WriteObject(&v22.Object{ID: i, Payload: make([]byte, 10_000)})
	}
	big.Close()
	g0, err := sub.AcceptSubgroup(ctx)
	if err != nil || g0.Header.Group != 0 {
		t.Fatalf("group 0: %v, %v", g0, err)
	}

	// Group 1 starts while group 0 is stuck; it must arrive in full.
	writeGroup(t, w, 1, 3)
	if g, got := readGroup(t, ctx, sub); g != 1 || len(got) != 3 {
		t.Fatalf("live group: %d %v", g, got)
	}

	// Stay congested on group 0 past the timeout: reading would grant
	// flow-control credit and let it drain.
	time.Sleep(500 * time.Millisecond)
	// The stale group 0 is reset once it lags the live edge by the timeout.
	var n int
	var readErr error
	for {
		if _, readErr = g0.Next(); readErr != nil {
			break
		}
		n++
	}
	if readErr == io.EOF || n >= 20 {
		t.Fatalf("stale group delivered in full (%d objects, %v); want it reset", n, readErr)
	}
	t.Logf("stale group reset after %d of 20 objects (%v)", n, readErr)
}
