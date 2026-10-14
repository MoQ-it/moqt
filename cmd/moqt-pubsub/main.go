// Command moqt-pubsub publishes or subscribes to a synthetic track, for
// exercising relays.
//
//	moqt-pubsub pub -url moqt://localhost:4443/moq -ns moqit/r1/p/alice -track clock
//	moqt-pubsub sub -url https://localhost:4443/moq -ns moqit/r1/p/alice -track clock
//
// moqt:// connects over raw QUIC; https:// over WebTransport.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/MoQ-it/moqt"
	"github.com/MoQ-it/moqt/transport/rawquic"
	"github.com/MoQ-it/moqt/transport/wt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "pub" && os.Args[1] != "sub") {
		fmt.Fprintln(os.Stderr, "usage: moqt-pubsub pub|sub -url URL -ns a/b/c -track NAME")
		os.Exit(2)
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	rawURL := fs.String("url", "moqt://localhost:4443/moq", "relay URL (moqt:// raw QUIC, https:// WebTransport)")
	ns := fs.String("ns", "moqt/demo", "track namespace, fields separated by /")
	name := fs.String("track", "clock", "track name")
	groups := fs.Int("groups", 0, "pub: stop after this many groups (0 = forever); sub: exit after this many")
	interval := fs.Duration("interval", 100*time.Millisecond, "pub: time between objects")
	perGroup := fs.Int("objects", 10, "pub: objects per group")
	fs.Parse(os.Args[2:])

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	track := v22.FullTrackName{Namespace: strings.Split(*ns, "/"), Name: *name}
	pub := &publisher{track: track, groups: *groups, perGroup: *perGroup, interval: *interval, log: log}
	var handler moqt.Handler = moqt.RejectAll{}
	if mode == "pub" {
		handler = pub
	}
	sess, err := dial(ctx, *rawURL, handler)
	if err != nil {
		log.Error("connect", "err", err)
		os.Exit(1)
	}
	defer sess.Close()

	if mode == "pub" {
		if _, err := sess.PublishNamespace(ctx, track.Namespace, nil); err != nil {
			log.Error("publish namespace", "err", err)
			os.Exit(1)
		}
		log.Info("publishing", "track", track)
		select {
		case <-ctx.Done():
		case <-sess.Context().Done():
			log.Error("session ended", "cause", context.Cause(sess.Context()))
		}
		return
	}
	if err := subscribe(ctx, sess, track, *groups, log); err != nil {
		log.Error("subscribe", "err", err)
		os.Exit(1)
	}
}

func dial(ctx context.Context, rawURL string, handler moqt.Handler) (*moqt.Session, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{InsecureSkipVerify: true} // development tool
	qconf := &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true, MaxIncomingUniStreams: 1 << 12}
	cfg := moqt.Config{Handler: handler}
	switch u.Scheme {
	case "moqt":
		tlsConf.NextProtos = []string{v22.ALPN}
		qc, err := quic.DialAddr(ctx, u.Host, tlsConf, qconf)
		if err != nil {
			return nil, err
		}
		pathOpt := u.EscapedPath()
		if u.RawQuery != "" {
			pathOpt += "?" + u.RawQuery
		}
		cfg.SetupOptions = v22.KeyValues{{Type: v22.OptAuthority, Bytes: []byte(u.Host)}, {Type: v22.OptPath, Bytes: []byte(pathOpt)}}
		return moqt.NewSession(ctx, rawquic.New(qc), moqt.Client, cfg)
	case "https":
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		tr := &webtransport.Transport{ApplicationProtocols: []string{v22.ALPN}, TLSClientConfig: tlsConf, QUICConfig: qconf}
		_, ws, err := tr.Dial(ctx, rawURL, nil)
		if err != nil {
			return nil, err
		}
		return moqt.NewSession(ctx, wt.New(ws), moqt.Client, cfg)
	}
	return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
}

// publisher serves a clock track: each object carries its send time.
type publisher struct {
	moqt.RejectAll
	track    v22.FullTrackName
	groups   int
	perGroup int
	interval time.Duration
	log      *slog.Logger
}

func (p *publisher) HandleSubscribe(r *moqt.SubscribeRequest) {
	if r.Track.Key() != p.track.Key() {
		r.Reject(v22.ReqErrDoesNotExist, "unknown track")
		return
	}
	w, err := r.Accept(moqt.AcceptOptions{Properties: v22.KeyValues{{Type: v22.PropDynamicGroups, Int: 1}}})
	if err != nil {
		return
	}
	p.log.Info("subscriber attached")
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for g := uint64(0); p.groups == 0 || g < uint64(p.groups); g++ {
		sg := w.OpenSubgroup(g, 0, moqt.SubgroupOptions{EndOfGroup: true, FirstObject: true})
		for o := range uint64(p.perGroup) {
			select {
			case <-w.Context().Done():
				sg.Reset(v22.ResetCancelled)
				p.log.Info("subscriber left")
				return
			case <-ticker.C:
			}
			payload := binary.BigEndian.AppendUint64(nil, uint64(time.Now().UnixNano()))
			if err := sg.WriteObject(&v22.Object{ID: o, Payload: payload}); err != nil {
				return
			}
		}
		sg.Close()
	}
	w.Close(v22.DoneTrackEnded, "")
}

func subscribe(ctx context.Context, sess *moqt.Session, track v22.FullTrackName, groups int, log *slog.Logger) error {
	sub, err := sess.Subscribe(ctx, track, &v22.Params{LocationFilter: &v22.LocationFilter{Type: v22.FilterRelativeStart, StartGroup: 1}})
	if err != nil {
		return err
	}
	log.Info("subscribed", "alias", sub.TrackAlias, "largest", sub.LargestObject)
	for n := 0; groups == 0 || n < groups; n++ {
		g, err := sub.AcceptSubgroup(ctx)
		if err == io.EOF {
			res, _ := sub.Result()
			log.Info("track ended", "status", res.StatusCode)
			return nil
		}
		if err != nil {
			return err
		}
		var count int
		var latency time.Duration
		for {
			o, err := g.Next()
			if err != nil {
				break
			}
			count++
			if len(o.Payload) == 8 {
				latency = time.Since(time.Unix(0, int64(binary.BigEndian.Uint64(o.Payload))))
			}
		}
		fmt.Printf("group %d: %d objects, last object latency %v\n", g.Header.Group, count, latency.Round(time.Microsecond))
	}
	sub.Unsubscribe()
	return nil
}
