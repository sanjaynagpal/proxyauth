package proxyauth

import (
	"net/http"
	"net/url"
	"testing"
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
