package proxyauth

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func hdr(vals ...string) http.Header {
	h := http.Header{}
	for _, v := range vals {
		h.Add("Proxy-Authenticate", v)
	}
	return h
}

func TestParseProxyAuthenticate(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want []challenge
	}{
		{
			name: "two separate headers",
			h:    hdr("Negotiate", "NTLM"),
			want: []challenge{{scheme: "Negotiate"}, {scheme: "NTLM"}},
		},
		{
			name: "comma separated in one header",
			h:    hdr("Negotiate, NTLM"),
			want: []challenge{{scheme: "Negotiate"}, {scheme: "NTLM"}},
		},
		{
			name: "token bearing challenge",
			h:    hdr("Negotiate oYG2MIGz"),
			want: []challenge{{scheme: "Negotiate", token: "oYG2MIGz"}},
		},
		{
			name: "basic alongside",
			h:    hdr("Negotiate", `Basic realm="corp"`),
			want: []challenge{{scheme: "Negotiate"}, {scheme: "Basic", token: `realm="corp"`}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseProxyAuthenticate(tc.h)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d challenges, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("challenge %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestChooseScheme(t *testing.T) {
	tests := []struct {
		name      string
		preferred []string
		offered   []challenge
		want      string
	}{
		{"prefers negotiate", []string{"Negotiate", "NTLM"}, []challenge{{scheme: "NTLM"}, {scheme: "Negotiate"}}, "Negotiate"},
		{"falls back to ntlm", []string{"Negotiate", "NTLM"}, []challenge{{scheme: "NTLM"}}, "NTLM"},
		{"case insensitive", []string{"Negotiate"}, []challenge{{scheme: "negotiate"}}, "negotiate"},
		{"nothing supported", []string{"Negotiate"}, []challenge{{scheme: "Basic"}}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := chooseScheme(tc.preferred, tc.offered); got != tc.want {
				t.Errorf("chooseScheme = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTokenForScheme(t *testing.T) {
	// "TlRMTVNTUAABAAAA" decodes to a byte sequence starting with "NTLMSSP\0".
	h := hdr("Negotiate TlRMTVNTUAABAAAA")
	raw, err := tokenForScheme(h, "Negotiate")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw[:7]) != "NTLMSSP" {
		t.Errorf("decoded token = %q, want it to start with NTLMSSP", raw)
	}

	// No token present -> nil, no error (valid empty input for SSPI).
	if raw, err := tokenForScheme(hdr("Negotiate"), "Negotiate"); err != nil || raw != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", raw, err)
	}

	// Invalid base64 -> error.
	if _, err := tokenForScheme(hdr("Negotiate !!!not-base64!!!"), "Negotiate"); err == nil {
		t.Error("expected an error for invalid base64 token")
	}
}

func TestProxyAddr(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"http://proxy.corp:3128", "proxy.corp:3128"},
		{"http://proxy.corp", "proxy.corp:80"},
		{"https://proxy.corp", "proxy.corp:443"},
	}
	for _, tc := range tests {
		u, err := url.Parse(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if got := proxyAddr(u); got != tc.want {
			t.Errorf("proxyAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestKeepAlive(t *testing.T) {
	if keepAlive(&http.Response{Close: true}) {
		t.Error("Close=true should not be keep-alive")
	}
	if keepAlive(&http.Response{Header: http.Header{"Proxy-Connection": {"close"}}}) {
		t.Error("Proxy-Connection: close should not be keep-alive")
	}
	if !keepAlive(&http.Response{Header: http.Header{"Proxy-Connection": {"Keep-Alive"}}}) {
		t.Error("Proxy-Connection: Keep-Alive should be keep-alive")
	}
}

// TestConnectSuccessDoesNotBlockOnBody is a regression test: a proxy's 200
// response to CONNECT has no body per RFC 7230 3.3.3 (the tunnel starts
// immediately after the header block), and commonly omits Content-Length.
// writeConnect used to unconditionally drain resp.Body after every leg,
// which for such a 200 blocks forever reading "until close" on a connection
// that's actually about to carry live tunnel traffic and never closes.
func TestConnectSuccessDoesNotBlockOnBody(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from origin")
	}))
	defer origin.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		// Deliberately no Content-Length: a compliant proxy need not send
		// one on a 2xx CONNECT response, and RFC 7230 says the client must
		// ignore it even if present.
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		oc, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			return
		}
		defer oc.Close()
		go io.Copy(oc, br)
		io.Copy(conn, oc)
	}()

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: New(Config{ProxyURL: proxyURL}),
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("request through unauthenticated tunnel failed (likely hung on the CONNECT body): %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello from origin" {
		t.Fatalf("got status=%d body=%q, want 200 %q", resp.StatusCode, body, "hello from origin")
	}
}

func TestSPNFor(t *testing.T) {
	tr := New(Config{})
	u, _ := url.Parse("http://proxy.corp.example:8080")
	if got := tr.spnFor(u); got != "HTTP/proxy.corp.example" {
		t.Errorf("spnFor = %q, want HTTP/proxy.corp.example", got)
	}
	tr2 := New(Config{SPN: "HTTP/custom.spn"})
	if got := tr2.spnFor(u); got != "HTTP/custom.spn" {
		t.Errorf("spnFor with override = %q, want HTTP/custom.spn", got)
	}
}
