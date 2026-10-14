package moqt_test

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/MoQ-it/moqt"
	"github.com/MoQ-it/moqt/transport/rawquic"
	v22 "github.com/MoQ-it/moqt/wire/v22"
	"github.com/quic-go/quic-go"
)

func tlsConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{v22.ALPN}}
}

// pair connects a client and a server session over QUIC on localhost.
func pair(t *testing.T, clientCfg, serverCfg moqt.Config) (client, server *moqt.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qcfg := &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 1000, MaxIncomingUniStreams: 1000}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConfig(t), qcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	type result struct {
		s   *moqt.Session
		err error
	}
	srvCh := make(chan result, 1)
	go func() {
		qc, err := ln.Accept(ctx)
		if err != nil {
			srvCh <- result{err: err}
			return
		}
		s, err := moqt.NewSession(ctx, rawquic.New(qc), moqt.Server, serverCfg)
		srvCh <- result{s, err}
	}()
	qc, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{v22.ALPN}}, qcfg)
	if err != nil {
		t.Fatal(err)
	}
	client, cerr := moqt.NewSession(ctx, rawquic.New(qc), moqt.Client, clientCfg)
	r := <-srvCh
	if cerr != nil || r.err != nil {
		t.Fatalf("setup: client %v, server %v", cerr, r.err)
	}
	t.Cleanup(func() { client.Close(); r.s.Close() })
	return client, r.s
}

// handler adapts funcs to moqt.Handler.
type handler struct {
	moqt.RejectAll
	subscribe          func(*moqt.SubscribeRequest)
	publishNamespace   func(*moqt.PublishNamespaceRequest)
	subscribeNamespace func(*moqt.SubscribeNamespaceRequest)
}

func (h *handler) HandleSubscribe(r *moqt.SubscribeRequest) {
	if h.subscribe == nil {
		h.RejectAll.HandleSubscribe(r)
		return
	}
	h.subscribe(r)
}
func (h *handler) HandlePublishNamespace(r *moqt.PublishNamespaceRequest) {
	if h.publishNamespace == nil {
		h.RejectAll.HandlePublishNamespace(r)
		return
	}
	h.publishNamespace(r)
}
func (h *handler) HandleSubscribeNamespace(r *moqt.SubscribeNamespaceRequest) {
	if h.subscribeNamespace == nil {
		h.RejectAll.HandleSubscribeNamespace(r)
		return
	}
	h.subscribeNamespace(r)
}

var track = v22.FullTrackName{Namespace: v22.Namespace{"moqit", "room1", "p", "alice"}, Name: "camera-h"}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestSetupAndAuth(t *testing.T) {
	token := []byte("secret")
	check := func(s *v22.Setup) error {
		kv, ok := s.Options.Get(v22.OptAuthorizationToken)
		if !ok {
			return errors.New("no token")
		}
		tok, err := v22.ParseToken(kv.Bytes)
		if err != nil || !bytes.Equal(tok.Value, token) {
			return errors.New("bad token")
		}
		return nil
	}
	opt := func(v []byte) moqt.Config {
		return moqt.Config{SetupOptions: v22.KeyValues{{Type: v22.OptAuthorizationToken, Bytes: v22.Token{AliasType: v22.AliasUseValue, Value: v}.Append(nil)}}}
	}
	client, server := pair(t, opt(token), moqt.Config{CheckSetup: check})
	impl, _ := server.PeerSetup().Options.Get(v22.OptMOQTImplementation)
	if string(impl.Bytes) != moqt.Implementation {
		t.Errorf("implementation option %q", impl.Bytes)
	}
	_ = client

	// A wrong token closes the session with UNAUTHORIZED.
	ctx := ctxT(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConfig(t), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() {
		qc, err := ln.Accept(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		_, err = moqt.NewSession(ctx, rawquic.New(qc), moqt.Server, moqt.Config{CheckSetup: check})
		srvErr <- err
	}()
	qc, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{v22.ALPN}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := moqt.NewSession(ctx, rawquic.New(qc), moqt.Client, opt([]byte("wrong")))
	var se *v22.SessionError
	if err := <-srvErr; !errors.As(err, &se) || se.Code != v22.ErrUnauthorized {
		t.Fatalf("server: %v; want UNAUTHORIZED", err)
	}
	if cs != nil {
		select {
		case <-cs.Context().Done():
		case <-time.After(2 * time.Second):
			t.Error("client session not closed after UNAUTHORIZED")
		}
	}
}

func TestSubscribeObjectsAndDone(t *testing.T) {
	const groups, perGroup = 3, 5
	writerDone := make(chan *moqt.TrackWriter, 1)
	h := &handler{subscribe: func(r *moqt.SubscribeRequest) {
		if r.Track.Name != track.Name || *r.Params.SubscriberPriority != 16 {
			r.Reject(v22.ReqErrDoesNotExist, "unexpected request")
			return
		}
		w, err := r.Accept(moqt.AcceptOptions{
			Properties:    v22.KeyValues{{Type: v22.PropDefaultPublisherPriority, Int: 96}, {Type: v22.PropDynamicGroups, Int: 1}},
			LargestObject: &v22.Location{Group: 9, Object: 4},
		})
		if err != nil {
			t.Error(err)
			return
		}
		for g := range uint64(groups) {
			sg := w.OpenSubgroup(10+g, 0, moqt.SubgroupOptions{Properties: true, EndOfGroup: true, FirstObject: true})
			for o := range uint64(perGroup) {
				obj := &v22.Object{ID: o, Payload: []byte(fmt.Sprintf("g%d-o%d", 10+g, o))}
				if o == 0 {
					obj.Properties = v22.KeyValues{{Type: 0x0C, Int: 33}}
				}
				if err := sg.WriteObject(obj); err != nil {
					t.Error(err)
				}
			}
			sg.Close()
		}
		// A subgroup with no Objects must not create a stream.
		w.OpenSubgroup(13, 0, moqt.SubgroupOptions{}).Close()
		writerDone <- w
	}}
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: h})
	ctx := ctxT(t)

	sub, err := client.Subscribe(ctx, track, &v22.Params{SubscriberPriority: new(uint8(16))})
	if err != nil {
		t.Fatal(err)
	}
	if sub.Info.PublisherPriority != 96 || !sub.Info.DynamicGroups || sub.LargestObject.Group != 9 {
		t.Errorf("track info %+v largest %+v", sub.Info, sub.LargestObject)
	}
	got := map[uint64][]string{}
	for range groups {
		g, err := sub.AcceptSubgroup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if id, ok := g.SubgroupID(); !ok || id != 0 || !g.Header.EndOfGroup {
			t.Errorf("subgroup header %+v", g.Header)
		}
		for {
			o, err := g.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.ID == 0 && len(o.Properties) != 1 {
				t.Errorf("object properties %+v", o.Properties)
			}
			got[g.Header.Group] = append(got[g.Header.Group], string(o.Payload))
		}
	}
	for g := uint64(10); g < 10+groups; g++ {
		if len(got[g]) != perGroup || got[g][perGroup-1] != fmt.Sprintf("g%d-o%d", g, perGroup-1) {
			t.Errorf("group %d: %v", g, got[g])
		}
	}

	w := <-writerDone
	if err := w.Close(v22.DoneTrackEnded, "bye"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.Done():
	case <-ctx.Done():
		t.Fatal("no PUBLISH_DONE")
	}
	done, err := sub.Result()
	if err != nil || done.StatusCode != v22.DoneTrackEnded || done.StreamCount != groups {
		t.Errorf("result %+v, %v; want TRACK_ENDED with %d streams", done, err, groups)
	}
}

func TestSubscribeRejected(t *testing.T) {
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &handler{subscribe: func(r *moqt.SubscribeRequest) {
		r.Reject(v22.ReqErrDoesNotExist, "no such track")
	}}})
	_, err := client.Subscribe(ctxT(t), track, nil)
	var re *moqt.RequestError
	if !errors.As(err, &re) || re.Code != v22.ReqErrDoesNotExist || re.Reason != "no such track" {
		t.Fatalf("got %v; want DOES_NOT_EXIST", err)
	}
	// Unhandled request types answer NOT_SUPPORTED.
	_, err = client.PublishNamespace(ctxT(t), track.Namespace, nil)
	if !errors.As(err, &re) || re.Code != v22.ReqErrNotSupported {
		t.Fatalf("got %v; want NOT_SUPPORTED", err)
	}
}

func TestDatagramsUpdatesAndUnsubscribe(t *testing.T) {
	writers := make(chan *moqt.TrackWriter, 1)
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &handler{subscribe: func(r *moqt.SubscribeRequest) {
		w, err := r.Accept(moqt.AcceptOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		writers <- w
	}}})
	ctx := ctxT(t)
	sub, err := client.Subscribe(ctx, track, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := <-writers

	// Datagrams.
	go func() {
		for i := range uint64(20) {
			w.WriteDatagram(&v22.Datagram{Group: i, Object: 0, Payload: []byte{byte(i)}})
		}
	}()
	d, err := sub.ReceiveDatagram(ctx)
	if err != nil || d.TrackAlias != sub.TrackAlias || len(d.Payload) != 1 {
		t.Fatalf("datagram %+v, %v", d, err)
	}

	// REQUEST_UPDATE reaches the publisher and is acknowledged.
	if !w.Forwarding() {
		t.Error("FORWARD should default to 1")
	}
	if err := sub.Update(ctx, &v22.Params{NewGroupRequest: new(uint64(0)), Forward: new(uint8(0))}); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-w.Updates():
		if p.NewGroupRequest == nil || *p.NewGroupRequest != 0 {
			t.Errorf("update %+v", p)
		}
	case <-ctx.Done():
		t.Fatal("update not delivered")
	}
	if w.Forwarding() {
		t.Error("FORWARD=0 not applied")
	}

	// Unsubscribe cancels the publisher's context.
	sub.Unsubscribe()
	select {
	case <-w.Context().Done():
		if !errors.Is(context.Cause(w.Context()), moqt.ErrSubscriberGone) {
			t.Errorf("cause %v", context.Cause(w.Context()))
		}
	case <-ctx.Done():
		t.Fatal("publisher not told about unsubscribe")
	}
	if _, err := sub.AcceptSubgroup(ctx); !errors.Is(err, moqt.ErrUnsubscribed) {
		t.Errorf("AcceptSubgroup after unsubscribe: %v", err)
	}
}

func TestNamespaces(t *testing.T) {
	accepted := make(chan *moqt.AcceptedNamespace, 1)
	announcers := make(chan *moqt.NamespaceAnnouncer, 1)
	client, _ := pair(t, moqt.Config{}, moqt.Config{Handler: &handler{
		publishNamespace: func(r *moqt.PublishNamespaceRequest) {
			a, err := r.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			accepted <- a
		},
		subscribeNamespace: func(r *moqt.SubscribeNamespaceRequest) {
			a, err := r.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			a.Announce(v22.Namespace{"p", "alice"})
			a.Announce(v22.Namespace{"p", "bob"})
			a.Withdraw(v22.Namespace{"p", "alice"})
			announcers <- a
		},
	}})
	ctx := ctxT(t)

	pn, err := client.PublishNamespace(ctx, track.Namespace, nil)
	if err != nil {
		t.Fatal(err)
	}
	an := <-accepted
	if an.Prefix.String() != track.Namespace.String() {
		t.Errorf("prefix %v", an.Prefix)
	}
	pn.Withdraw()
	select {
	case <-an.Done():
	case <-ctx.Done():
		t.Fatal("withdrawal not seen")
	}

	ns, err := client.SubscribeNamespace(ctx, v22.Namespace{"moqit", "room1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for range 3 {
		e, err := ns.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, fmt.Sprintf("%v:%v", e.Suffix, e.Active))
	}
	if want := "[p-alice:true p-bob:true p-alice:false]"; fmt.Sprint(events) != want {
		t.Errorf("events %v; want %s", events, want)
	}
	a := <-announcers
	ns.Cancel()
	select {
	case <-a.Done():
	case <-ctx.Done():
		t.Fatal("namespace subscriber cancel not seen")
	}
}

func TestGoAway(t *testing.T) {
	client, server := pair(t, moqt.Config{}, moqt.Config{})
	if err := server.GoAway("https://node-b.example/moq", 3*time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.GoAwayReceived():
		if g := client.PeerGoAway(); g.NewSessionURI != "https://node-b.example/moq" || g.Timeout != 3000 {
			t.Errorf("goaway %+v", g)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GOAWAY not received")
	}
	if err := client.GoAway("https://x", 0); err == nil {
		t.Error("client GOAWAY with URI must fail")
	}
}
