//go:build browser

// End-to-end test of the TypeScript client in real browsers against the Go
// relay. Run with: go test -tags browser ./ts/e2e
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MoQ-it/moqt"
	"github.com/MoQ-it/moqt/relay"
	"github.com/MoQ-it/moqt/transport/rawquic"
	"github.com/MoQ-it/moqt/transport/wt"
	v22 "github.com/MoQ-it/moqt/wire/v22"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

type browserResult struct {
	UA          string `json:"ua"`
	Connected   bool   `json:"connected"`
	OK          bool   `json:"ok"`
	Error       string `json:"error"`
	PublishedTo string `json:"publishedTo"`
	Received    []struct {
		Group   uint64   `json:"group"`
		Objects []string `json:"objects"`
	} `json:"received"`
}

func TestChrome(t *testing.T) {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		t.Skip("google-chrome not installed")
	}
	run(t, func(url, dir string) *exec.Cmd {
		return exec.Command(chrome, "--headless=new", "--no-sandbox", "--user-data-dir="+filepath.Join(dir, "chrome"), url)
	})
}

func TestFirefox(t *testing.T) {
	firefox, err := exec.LookPath("firefox")
	if err != nil {
		t.Skip("firefox not installed")
	}
	run(t, func(url, dir string) *exec.Cmd {
		// The snap build cannot read /tmp, so the profile lives in the repo.
		prof, err := os.MkdirTemp(".", ".ff-profile-")
		if err != nil {
			t.Fatal(err)
		}
		abs, _ := filepath.Abs(prof)
		t.Cleanup(func() { os.RemoveAll(abs) })
		os.WriteFile(filepath.Join(abs, "user.js"), []byte(`user_pref("dom.allow_scripts_to_close_windows", true);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
`), 0o644)
		return exec.Command(firefox, "--headless", "--no-remote", "--profile", abs, url)
	})
}

func run(t *testing.T, browser func(url, dir string) *exec.Cmd) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir := t.TempDir()

	bundle := filepath.Join(dir, "bundle.js")
	if out, err := exec.Command("npx", "esbuild", "browser.ts", "--bundle", "--format=esm", "--outfile="+bundle).CombinedOutput(); err != nil {
		t.Fatalf("esbuild: %v\n%s", err, out)
	}

	cert, hash := selfSigned(t)
	relayAddr := startRelay(t, cert)

	// Go publisher of e2e/go/clock over raw QUIC.
	pubSess := dial(t, ctx, relayAddr, &clockPublisher{})
	if _, err := pubSess.PublishNamespace(ctx, v22.Namespace{"e2e", "go"}, nil); err != nil {
		t.Fatal(err)
	}

	results := make(chan browserResult, 1)
	goDone := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><script type="module" src="/bundle.js"></script>`)
	})
	mux.HandleFunc("/bundle.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		http.ServeFile(w, r, bundle)
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"url": "https://127.0.0.1:" + portOf(relayAddr) + "/moq", "certHash": hash})
	})
	mux.HandleFunc("/go-done", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-goDone:
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/result", func(w http.ResponseWriter, r *http.Request) {
		var res browserResult
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &res)
		results <- res
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	cmd := browser("http://localhost:"+portOf(ln.Addr().String())+"/", dir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	// Go subscriber of the browser's track, retried until the browser has
	// published its namespace.
	subSess := dial(t, ctx, relayAddr, nil)
	var sub *moqt.Subscription
	for sub == nil {
		sub, err = subSess.Subscribe(ctx, v22.FullTrackName{Namespace: v22.Namespace{"e2e", "browser"}, Name: "cam"}, nil)
		if err != nil {
			select {
			case res := <-results:
				t.Fatalf("browser finished before publishing: %+v", res)
			case <-ctx.Done():
				t.Fatalf("subscribing to the browser's track: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	var got []string
	for {
		g, err := sub.AcceptSubgroup(ctx)
		if err != nil {
			break // PUBLISH_DONE
		}
		for {
			o, err := g.Next()
			if err != nil {
				break
			}
			got = append(got, string(o.Payload))
		}
	}
	done, err := sub.Result()
	close(goDone)
	if err != nil || done == nil || done.StatusCode != v22.DoneTrackEnded || done.StreamCount != 3 {
		t.Errorf("browser track result %+v, %v; want TRACK_ENDED with 3 streams", done, err)
	}
	if len(got) != 15 || got[0] != "browser 0/0" || got[14] != "browser 2/4" {
		t.Errorf("objects from the browser: %v", got)
	}

	select {
	case res := <-results:
		t.Logf("browser: %s", res.UA)
		if !res.OK {
			t.Fatalf("browser failed: %s", res.Error)
		}
		if len(res.Received) != 3 {
			t.Fatalf("browser received %d groups", len(res.Received))
		}
		for i, g := range res.Received {
			if len(g.Objects) == 0 || (i > 0 && g.Group != res.Received[i-1].Group+1) {
				t.Errorf("browser group %d: %+v", i, g)
			}
		}
		t.Logf("browser received groups %d..%d, e.g. %v", res.Received[0].Group, res.Received[2].Group, res.Received[2].Objects)
	case <-ctx.Done():
		t.Fatal("no result from the browser")
	}
}

// clockPublisher publishes e2e/go/clock: groups of 5 objects, one every 10ms.
type clockPublisher struct{ moqt.RejectAll }

func (clockPublisher) HandleSubscribe(r *moqt.SubscribeRequest) {
	w, err := r.Accept(moqt.AcceptOptions{})
	if err != nil {
		return
	}
	for g := uint64(0); ; g++ {
		sg := w.OpenSubgroup(g, 0, moqt.SubgroupOptions{EndOfGroup: true})
		for o := range uint64(5) {
			select {
			case <-w.Context().Done():
				sg.Reset(v22.ResetCancelled)
				return
			case <-time.After(10 * time.Millisecond):
			}
			if err := sg.WriteObject(&v22.Object{ID: o, Payload: []byte(fmt.Sprintf("go %d/%d", g, o))}); err != nil {
				return
			}
		}
		sg.Close()
	}
}

func selfSigned(t *testing.T) (tls.Certificate, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// serverCertificateHashes requires ECDSA, under 14 days of validity, and
	// a server-auth leaf certificate.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "moqt-e2e"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, fmt.Sprintf("%x", sum)
}

// startRelay serves the relay on one UDP socket: raw QUIC and WebTransport.
func startRelay(t *testing.T, cert tls.Certificate) string {
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{v22.ALPN, http3.NextProtoH3}}
	qconf := &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true, MaxIncomingStreams: 1000, MaxIncomingUniStreams: 1000}
	r := relay.New(relay.Config{})
	serve := func(c moqt.Conn) {
		peer := r.NewPeer(nil)
		s, err := moqt.NewSession(context.Background(), c, moqt.Server, moqt.Config{Handler: peer})
		if err == nil {
			peer.Attach(s)
		}
	}
	h3 := &http3.Server{TLSConfig: tlsConf, QUICConfig: qconf}
	webtransport.ConfigureHTTP3Server(h3)
	wts := &webtransport.Server{H3: h3, ApplicationProtocols: []string{v22.ALPN}, CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/moq", func(w http.ResponseWriter, req *http.Request) {
		sess, err := wts.Upgrade(w, req)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		serve(wt.New(sess))
	})
	h3.Handler = mux
	ln, err := quic.ListenAddrEarly("127.0.0.1:0", tlsConf, qconf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); wts.Close() })
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			if c.ConnectionState().TLS.NegotiatedProtocol == v22.ALPN {
				go serve(rawquic.New(c))
			} else {
				go func() {
					if err := wts.ServeQUICConn(c); err != nil {
						t.Logf("serve webtransport: %v", err)
					}
				}()
			}
		}
	}()
	return ln.Addr().String()
}

func dial(t *testing.T, ctx context.Context, addr string, h moqt.Handler) *moqt.Session {
	qc, err := quic.DialAddr(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{v22.ALPN}}, &quic.Config{EnableDatagrams: true, MaxIncomingUniStreams: 1000})
	if err != nil {
		t.Fatal(err)
	}
	s, err := moqt.NewSession(ctx, rawquic.New(qc), moqt.Client, moqt.Config{Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func portOf(addr string) string { return addr[strings.LastIndex(addr, ":")+1:] }
