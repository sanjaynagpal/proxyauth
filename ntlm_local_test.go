//go:build windows

package proxyauth

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/alexbrainman/sspi/ntlm"
)

func dbg(format string, args ...any) { fmt.Fprintf(os.Stderr, "[fakeproxy] "+format+"\n", args...) }

// fakeNTLMProxy is a minimal forward proxy that plays the server side of NTLM
// over CONNECT, using SSPI to validate against the local machine (no domain
// controller required). It exists to exercise Transport.connect's real
// multi-leg handshake and auth_windows.go's SSPI calls end-to-end, which the
// table-driven tests in proxyauth_test.go deliberately don't touch.
type fakeNTLMProxy struct {
	ln net.Listener
}

func startFakeNTLMProxy(t *testing.T) *fakeNTLMProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &fakeNTLMProxy{ln: ln}
	go p.serve()
	return p
}

func (p *fakeNTLMProxy) url() string {
	return "http://" + p.ln.Addr().String()
}

func (p *fakeNTLMProxy) close() { p.ln.Close() }

func (p *fakeNTLMProxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go p.handle(conn)
	}
}

func (p *fakeNTLMProxy) handle(conn net.Conn) {
	defer conn.Close()
	dbg("accepted connection from %s", conn.RemoteAddr())
	br := bufio.NewReader(conn)

	// Leg 0: unauthenticated CONNECT -> 407 advertising NTLM.
	req, err := http.ReadRequest(br)
	if err != nil {
		dbg("leg0 read: %v", err)
		return
	}
	io.Copy(io.Discard, req.Body)
	dbg("leg0: got CONNECT %s", req.Host)
	if _, err := fmt.Fprint(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
		"Proxy-Authenticate: NTLM\r\n"+
		"Proxy-Connection: Keep-Alive\r\n"+
		"Content-Length: 0\r\n\r\n"); err != nil {
		dbg("leg0 write: %v", err)
		return
	}

	// Leg 1: Proxy-Authorization: NTLM <base64 Type1> -> SSPI produces Type2
	// challenge -> 407 carrying it.
	req, err = http.ReadRequest(br)
	if err != nil {
		dbg("leg1 read: %v", err)
		return
	}
	io.Copy(io.Discard, req.Body)
	type1, err := decodeNTLM(req.Header.Get("Proxy-Authorization"))
	if err != nil {
		dbg("leg1 decode: %v", err)
		return
	}
	dbg("leg1: got Type1, %d bytes", len(type1))

	cred, err := ntlm.AcquireServerCredentials()
	if err != nil {
		dbg("AcquireServerCredentials: %v", err)
		return
	}
	defer cred.Release()

	sc, type2, err := ntlm.NewServerContext(cred, type1)
	if err != nil {
		dbg("NewServerContext: %v", err)
		return
	}
	defer sc.Release()
	dbg("leg1: NewServerContext ok, Type2 %d bytes", len(type2))

	if _, err := fmt.Fprintf(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
		"Proxy-Authenticate: NTLM %s\r\n"+
		"Proxy-Connection: Keep-Alive\r\n"+
		"Content-Length: 0\r\n\r\n", base64.StdEncoding.EncodeToString(type2)); err != nil {
		dbg("leg1 write: %v", err)
		return
	}

	// Leg 2: Proxy-Authorization: NTLM <base64 Type3> -> SSPI validates ->
	// 200 and the connection becomes a raw tunnel to the origin.
	req, err = http.ReadRequest(br)
	if err != nil {
		dbg("leg2 read: %v", err)
		return
	}
	io.Copy(io.Discard, req.Body)
	type3, err := decodeNTLM(req.Header.Get("Proxy-Authorization"))
	if err != nil {
		dbg("leg2 decode: %v", err)
		return
	}
	dbg("leg2: got Type3, %d bytes", len(type3))
	if err := sc.Update(type3); err != nil {
		dbg("NTLM validation failed: %v", err)
		fmt.Fprint(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	dbg("leg2: NTLM validation OK")

	origin := req.Host // authority-form target the client asked to CONNECT to
	dbg("dialing origin %s", origin)
	oc, err := net.DialTimeout("tcp", origin, 5*time.Second)
	if err != nil {
		dbg("dial origin %s: %v", origin, err)
		fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer oc.Close()
	dbg("dialed origin %s ok", origin)

	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		dbg("writing 200: %v", err)
		return
	}
	dbg("wrote 200, relaying")

	// Relay raw bytes both ways: NTLM only authenticates the tunnel, it
	// doesn't touch what flows through it afterward.
	done := make(chan struct{}, 2)
	go func() {
		n, err := io.Copy(oc, br)
		dbg("relay client->origin done: n=%d err=%v", n, err)
		done <- struct{}{}
	}()
	go func() {
		n, err := io.Copy(conn, oc)
		dbg("relay origin->client done: n=%d err=%v", n, err)
		done <- struct{}{}
	}()
	<-done
}

func decodeNTLM(proxyAuth string) ([]byte, error) {
	const prefix = "NTLM "
	if len(proxyAuth) <= len(prefix) {
		return nil, fmt.Errorf("missing NTLM token in %q", proxyAuth)
	}
	return base64.StdEncoding.DecodeString(proxyAuth[len(prefix):])
}

// TestNTLMHandshakeLocal drives Transport through a full NTLM CONNECT
// handshake against fakeNTLMProxy, then a real HTTP request over the
// resulting tunnel to an httptest origin. It authenticates as the
// currently logged-in user (SSO) against SSPI's local machine validation,
// so it needs no domain controller — just a Windows session with a
// normal logon.
func TestNTLMHandshakeLocal(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from origin")
	}))
	defer origin.Close()

	proxy := startFakeNTLMProxy(t)
	defer proxy.close()

	proxyURL, err := url.Parse(proxy.url())
	if err != nil {
		t.Fatal(err)
	}

	tr := New(Config{
		ProxyURL: proxyURL,
		Schemes:  []string{"NTLM"},
	})
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("request through NTLM tunnel failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello from origin" {
		t.Fatalf("got status=%d body=%q, want 200 %q", resp.StatusCode, body, "hello from origin")
	}
}

