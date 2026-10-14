package wt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/MoQ-it/moqt"
	"github.com/MoQ-it/moqt/transport/wt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

type publisher struct{ moqt.RejectAll }

// HandleSubscribe answers with one group of three objects, then PUBLISH_DONE.
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

func TestOverWebTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Server{TLSConfig: tlsConf, QUICConfig: &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true}}
	webtransport.ConfigureHTTP3Server(h3)
	srv := &webtransport.Server{H3: h3, ApplicationProtocols: []string{v22.ALPN}, CheckOrigin: func(*http.Request) bool { return true }}
	defer srv.Close()

	serverErr := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/moq", func(w http.ResponseWriter, r *http.Request) {
		sess, err := srv.Upgrade(w, r)
		if err != nil {
			serverErr <- err
			return
		}
		if p := sess.SessionState().ApplicationProtocol; p != v22.ALPN {
			serverErr <- &v22.SessionError{Reason: "negotiated " + p}
			return
		}
		_, err = moqt.NewSession(ctx, wt.New(sess), moqt.Server, moqt.Config{Handler: publisher{}})
		serverErr <- err
	})
	h3.Handler = mux
	go srv.Serve(pc)

	tr := &webtransport.Transport{
		ApplicationProtocols: []string{v22.ALPN},
		TLSClientConfig:      &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:           &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
	}
	defer tr.Close()
	_, wsess, err := tr.Dial(ctx, "https://localhost:"+itoa(pc.LocalAddr().(*net.UDPAddr).Port)+"/moq", nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := moqt.NewSession(ctx, wt.New(wsess), moqt.Client, moqt.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}

	sub, err := client.Subscribe(ctx, v22.FullTrackName{Namespace: v22.Namespace{"moqit", "r"}, Name: "mic"}, nil)
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

func itoa(n int) string {
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
