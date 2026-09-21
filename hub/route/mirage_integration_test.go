package route

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/mirage"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	"github.com/metacubex/mihomo/tunnel"
	M "github.com/metacubex/sing/common/metadata"
)

// Full loopback integration: real Chrome/uTLS -> AnyTLS password/session ->
// verified inner HTTPS with complete body, without external internet or a phone.
func TestMirageRealAnyTLSAuthenticatedHTTPS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: miragePayloadHost},
		DNSNames: []string{miragePayloadHost, "node.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := ca.AddCertificate(string(certPEM)); err != nil {
		t.Fatal(err)
	}
	cert := stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	var payloads atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
				header := make([]byte, 34)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				hash := sha256.Sum256([]byte("correct-password"))
				if string(header[:32]) != string(hash[:]) {
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(header[32:]))); err != nil {
					return
				}
				var scheme atomic.Pointer[padding.PaddingFactory]
				padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &scheme)
				s := session.NewServerSession(conn, func(stream *session.Stream) {
					defer stream.Close()
					destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
					if err != nil || destination.Fqdn != miragePayloadHost || destination.Port != 443 {
						return
					}
					if err := stream.HandshakeSuccess(); err != nil {
						return
					}
					inner := stdtls.Server(stream, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
					defer inner.Close()
					request, err := stdhttp.ReadRequest(bufio.NewReader(inner))
					if err != nil || request.Host != miragePayloadHost || request.URL.RequestURI() != "/__down?bytes=32768" {
						return
					}
					payloads.Add(1)
					_, _ = fmt.Fprintf(inner, "HTTP/1.1 200 OK\r\nContent-Length: 32768\r\nConnection: close\r\n\r\n%s", strings.Repeat("x", 32768))
				}, &scheme)
				s.Run()
				s.Close()
			}()
		}
	}()
	host, portString, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	previous, providers := tunnel.Proxies(), tunnel.Providers()
	defer tunnel.UpdateProxies(previous, providers)
	for i, password := range []string{"correct-password", "correct-password", "wrong-password"} {
		// Exercise the production parser: it wraps every concrete node in an
		// auto-close adapter, unlike a direct NewAnyTLS test fixture.
		proxy, err := adapter.ParseProxy(map[string]any{"type": "anytls", "name": "node", "server": host,
			"port": port, "password": password, "sni": "node.example", "client-fingerprint": "chrome"},
			adapter.WithTunnelForAPI(tunnel.Tunnel))
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()
		tunnel.UpdateProxies(map[string]C.Proxy{"PROXY": proxy}, nil)
		node, revision := selectedMirageOutbound()
		if node == nil || revision == "" {
			t.Fatal("production-parsed AnyTLS was not recognized")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		result := executeMirageProbe(ctx, node, mirage.Shape{5, 2, false}, node.MirageRevision())
		cancel()
		proxy.Close()
		if result["closed"] != true {
			t.Fatal("closure not acknowledged")
		}
		if i < 2 {
			if result["ok"] != true || result["authenticated"] != true || result["receivedBytes"] != 32768 {
				t.Fatalf("real probe failed: %+v", result)
			}
		} else if result["ok"] == true {
			t.Fatal("wrong AnyTLS password was accepted")
		}
	}
	if accepted.Load() != 3 || payloads.Load() != 2 {
		t.Fatalf("cold connections=%d authenticated payloads=%d", accepted.Load(), payloads.Load())
	}
}
