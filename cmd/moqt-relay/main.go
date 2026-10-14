// Command moqt-relay is a standalone MOQT relay. One UDP socket serves
// both raw QUIC (ALPN moqt-22) and WebTransport (ALPN h3, path -path), so
// native clients, other relays and browsers can all connect.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
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

func main() {
	addr := flag.String("addr", ":4443", "UDP listen address")
	path := flag.String("path", "/moq", "WebTransport path")
	certFile := flag.String("cert", "", "TLS certificate (default: self-signed, 13 days, for serverCertificateHashes)")
	keyFile := flag.String("key", "", "TLS key")
	hosts := flag.String("hosts", "localhost,127.0.0.1", "names for the self-signed certificate")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cert, err := loadCert(*certFile, *keyFile, *hosts, log)
	if err != nil {
		log.Error("certificate", "err", err)
		os.Exit(1)
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{v22.ALPN, http3.NextProtoH3}}
	qconf := &quic.Config{
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		MaxIncomingStreams:               1 << 12,
		MaxIncomingUniStreams:            1 << 14,
		KeepAlivePeriod:                  10 * time.Second,
	}

	r := relay.New(relay.Config{Logger: log})

	h3 := &http3.Server{TLSConfig: tlsConf, QUICConfig: qconf}
	webtransport.ConfigureHTTP3Server(h3)
	wts := &webtransport.Server{H3: h3, ApplicationProtocols: []string{v22.ALPN}, CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc(*path, func(w http.ResponseWriter, req *http.Request) {
		sess, err := wts.Upgrade(w, req)
		if err != nil {
			log.Warn("webtransport upgrade", "err", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if p := sess.SessionState().ApplicationProtocol; p != v22.ALPN {
			sess.CloseWithError(0, "unsupported protocol "+p)
			return
		}
		serve(r, wt.New(sess), req.RemoteAddr, log)
	})
	h3.Handler = mux

	ln, err := quic.ListenAddrEarly(*addr, tlsConf, qconf)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	log.Info("relay listening", "addr", *addr, "webtransport", "https://<host>"+portOf(*addr)+*path, "alpn", []string{v22.ALPN, http3.NextProtoH3})
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Error("accept", "err", err)
			os.Exit(1)
		}
		switch conn.ConnectionState().TLS.NegotiatedProtocol {
		case v22.ALPN:
			go serve(r, rawquic.New(conn), conn.RemoteAddr().String(), log)
		case http3.NextProtoH3:
			go wts.ServeQUICConn(conn)
		default:
			conn.CloseWithError(0x10, "unsupported ALPN")
		}
	}
}

func serve(r *relay.Relay, conn moqt.Conn, remote string, log *slog.Logger) {
	peer := r.NewPeer(remote)
	l := log.With("remote", remote, "webtransport", conn.WebTransport())
	s, err := moqt.NewSession(context.Background(), conn, moqt.Server, moqt.Config{Handler: peer, Logger: l})
	if err != nil {
		l.Warn("session setup failed", "err", err)
		return
	}
	peer.Attach(s)
	l.Info("session started")
	<-s.Context().Done()
	l.Info("session ended", "cause", context.Cause(s.Context()))
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return ":" + p
	}
	return ""
}

func loadCert(certFile, keyFile, hosts string, log *slog.Logger) (tls.Certificate, error) {
	if certFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "moqt-relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(13 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for h := range strings.SplitSeq(hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	sum := sha256.Sum256(der)
	log.Info("self-signed certificate (use as WebTransport serverCertificateHashes)", "sha256", fmt.Sprintf("%x", sum))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
