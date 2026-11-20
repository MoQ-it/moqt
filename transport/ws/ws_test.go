package ws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MoQ-it/moqt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
	"github.com/coder/websocket"
)

func TestFrameRoundTrip(t *testing.T) {
	for _, b := range [][]byte{
		appendStream(nil, 6, false, []byte("abc")),
		appendStream(nil, 1<<40, true, nil),
		appendCode(nil, frameResetStream, 3, 0x12),
		appendCode(nil, frameStopSending, 2, 0),
		appendDatagram(nil, []byte{1, 2}),
		appendClose(nil, 0x10, "bye"),
	} {
		f, err := parseFrame(b)
		if err != nil {
			t.Fatalf("%x: %v", b, err)
		}
		var again []byte
		switch f.typ {
		case frameStream:
			again = appendStream(nil, f.id, f.fin, f.data)
		case frameResetStream, frameStopSending:
			again = appendCode(nil, f.typ, f.id, f.code)
		case frameDatagram:
			again = appendDatagram(nil, f.data)
		case frameClose:
			again = appendClose(nil, f.code, string(f.data))
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("%x re-encoded as %x", b, again)
		}
	}
	for _, b := range [][]byte{{}, {0x08}, {0x04, 0x01}, {0x04, 0x01, 0x02, 0x03}, {0x1d}, {0x3f}} {
		if _, err := parseFrame(b); err == nil {
			t.Errorf("%x parsed", b)
		}
	}
}

func TestStreamIDs(t *testing.T) {
	for _, c := range []struct {
		count       uint64
		uni, server bool
		want        uint64
	}{{0, false, false, 0}, {0, false, true, 1}, {0, true, false, 2}, {0, true, true, 3}, {5, true, true, 23}} {
		if got := streamID(c.count, c.uni, c.server); got != c.want {
			t.Errorf("streamID(%d, %v, %v) = %d, want %d", c.count, c.uni, c.server, got, c.want)
		}
	}
}

// pair connects a client and a server Conn over a real WebSocket.
func pair(t *testing.T) (client, server *Conn) {
	t.Helper()
	ch := make(chan *Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Accept(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		ch <- c
		<-c.Context().Done()
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.CloseWithError(0, "") })
	return client, <-ch
}

func TestRejectsOtherSubprotocols(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := Accept(w, r); err == nil {
			t.Error("accepted a client without the subprotocol")
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	if _, _, err := c.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("read: %v", err)
	}
}

func TestStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, server := pair(t)

	// A bidirectional stream carries data and FIN both ways.
	bs, _ := client.OpenStreamSync(ctx)
	big := bytes.Repeat([]byte("x"), 3*maxChunk+5)
	if _, err := bs.Write(big); err != nil {
		t.Fatal(err)
	}
	bs.Close()
	peer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("read %d bytes, %v", len(got), err)
	}
	peer.Write([]byte("pong"))
	peer.Close()
	if got, err := io.ReadAll(bs); err != nil || string(got) != "pong" {
		t.Fatalf("reply %q, %v", got, err)
	}

	// Streams opened later but written first implicitly open earlier ones.
	u1, _ := server.OpenUniStreamSync(ctx)
	u2, _ := server.OpenUniStreamSync(ctx)
	u2.Write([]byte("two"))
	u2.Close()
	u1.Write([]byte("one"))
	u1.Close()
	for _, want := range []string{"one", "two"} {
		r, err := client.AcceptUniStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := io.ReadAll(r); string(got) != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}

	// A reset reaches the reader with its code.
	u3, _ := client.OpenUniStreamSync(ctx)
	u3.Write([]byte("partial"))
	u3.CancelWrite(0x7)
	r, err := server.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var se *StreamError
	for {
		if _, err = r.Read(make([]byte, 64)); err != nil {
			break
		}
	}
	if !errors.As(err, &se) || se.Code != 0x7 || !se.Remote {
		t.Fatalf("read after reset: %v", err)
	}

	// STOP_SENDING fails the writer and cancels its context.
	u4, _ := client.OpenUniStreamSync(ctx)
	u4.Write([]byte("hi"))
	r, err = server.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.CancelRead(0x9)
	select {
	case <-u4.Context().Done():
	case <-ctx.Done():
		t.Fatal("writer context not cancelled by STOP_SENDING")
	}
	if _, err := u4.Write([]byte("more")); !errors.As(err, &se) || se.Code != 0x9 {
		t.Fatalf("write after STOP_SENDING: %v", err)
	}

	// Datagrams arrive.
	client.SendDatagram([]byte("dg"))
	if d, err := server.ReceiveDatagram(ctx); err != nil || string(d) != "dg" {
		t.Fatalf("datagram %q, %v", d, err)
	}
}

// The most urgent stream's data goes first, whatever order it was written in.
func TestPriority(t *testing.T) {
	c := &Conn{work: make(chan struct{}, 1), streams: map[uint64]*stream{}, ready: map[*stream]struct{}{}}
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	defer c.cancel(nil)
	low, _ := c.open(true)
	low.SetPriority(200)
	high, _ := c.open(true)
	high.SetPriority(10)
	low.Write(bytes.Repeat([]byte("l"), 2*maxChunk))
	high.Write([]byte("h"))
	var order []uint64
	for {
		f, _ := c.nextFrame()
		if f == nil {
			break
		}
		p, _ := parseFrame(f)
		order = append(order, p.id)
	}
	if len(order) != 3 || order[0] != high.id {
		t.Fatalf("frame order %v, want stream %d first", order, high.id)
	}
}

// A writer blocks once its stream has sendBuffer queued, until a reset
// unblocks it.
func TestWriteBackpressure(t *testing.T) {
	c := &Conn{work: make(chan struct{}, 1), streams: map[uint64]*stream{}, ready: map[*stream]struct{}{}}
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	defer c.cancel(nil)
	s, _ := c.open(true)
	s.Write(make([]byte, sendBuffer))
	done := make(chan error, 1)
	go func() {
		_, err := s.Write([]byte("more"))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("write did not block: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	s.CancelWrite(1)
	if err := <-done; err == nil {
		t.Fatal("blocked write succeeded after reset")
	}
	f, _ := c.nextFrame()
	if p, err := parseFrame(f); err != nil || p.typ != frameResetStream || p.code != 1 {
		t.Fatalf("frame after reset: %+v, %v", p, err)
	}
}

func TestCloseReachesPeer(t *testing.T) {
	client, server := pair(t)
	server.CloseWithError(0x10, "bye")
	select {
	case <-client.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client not closed")
	}
	var ce *CloseError
	if err := context.Cause(client.Context()); !errors.As(err, &ce) || ce.Code != 0x10 || ce.Reason != "bye" || !ce.Remote {
		t.Fatalf("cause %v", err)
	}
}

type publisher struct{ moqt.RejectAll }

func (publisher) HandleSubscribe(r *moqt.SubscribeRequest) {
	w, err := r.Accept(moqt.AcceptOptions{})
	if err != nil {
		return
	}
	sg := w.OpenSubgroup(0, 0, moqt.SubgroupOptions{EndOfGroup: true})
	for i := range uint64(3) {
		sg.WriteObject(&v22.Object{ID: i, Payload: []byte{'a' + byte(i)}})
	}
	sg.Close()
	w.Close(v22.DoneTrackEnded, "")
}

func TestMOQTSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, server := pair(t)
	serverErr := make(chan error, 1)
	go func() {
		_, err := moqt.NewSession(ctx, server, moqt.Server, moqt.Config{Handler: publisher{}})
		serverErr <- err
	}()
	sess, err := moqt.NewSession(ctx, client, moqt.Client, moqt.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	sub, err := sess.Subscribe(ctx, v22.FullTrackName{Namespace: v22.Namespace{"moqit", "r"}, Name: "mic"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := sub.AcceptSubgroup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for {
		o, err := g.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, o.Payload...)
	}
	if string(got) != "abc" {
		t.Fatalf("payloads %q", got)
	}
	<-sub.Done()
	if done, err := sub.Result(); err != nil || done.StreamCount != 1 {
		t.Fatalf("result %+v, %v", done, err)
	}
}
