package proxyauth

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrUnsupportedPlatform is returned when a proxy requires SSPI authentication
// but the program is not running on Windows.
var ErrUnsupportedPlatform = errors.New("proxyauth: SSPI proxy authentication is only supported on Windows")

// Config configures a Transport. The zero value is usable: it discovers the
// proxy from the environment (HTTPS_PROXY/HTTP_PROXY/NO_PROXY), authenticates as
// the current Windows user, and prefers Negotiate over NTLM.
type Config struct {
	// ProxyURL, if set, forces all proxied traffic through this proxy and
	// ignores the environment. Ignored when Proxy is set.
	ProxyURL *url.URL

	// Proxy, if set, selects the proxy per request exactly like
	// http.Transport.Proxy. Returning (nil, nil) means "no proxy for this
	// request" (the request is dialed directly). Takes precedence over
	// ProxyURL. When both Proxy and ProxyURL are nil, the environment is used
	// via http.ProxyFromEnvironment.
	Proxy func(*http.Request) (*url.URL, error)

	// Schemes lists the proxy authentication schemes to use, in order of
	// preference. Supported values are "Negotiate" and "NTLM" (case
	// insensitive). Defaults to {"Negotiate", "NTLM"}.
	Schemes []string

	// SPN overrides the Kerberos service principal name presented to SSPI.
	// When empty it defaults to "HTTP/<proxy-host>" (the proxy host without
	// its port). Use the proxy's fully-qualified name for Kerberos to succeed.
	SPN string

	// Domain, Username, Password provide explicit credentials. When Username is
	// empty (the default) the logged-in user's credentials are used (SSO).
	Domain   string
	Username string
	Password string

	// TLSClientConfig is used for the TLS handshake to the ORIGIN server (over
	// the established tunnel). Optional.
	TLSClientConfig *tls.Config

	// ProxyTLSClientConfig is used only when the proxy URL scheme is "https"
	// (i.e. the connection to the proxy itself is TLS). Optional.
	ProxyTLSClientConfig *tls.Config

	// DialContext dials raw TCP connections (to the proxy, or directly to the
	// origin for NO_PROXY hosts). Defaults to a net.Dialer with sane timeouts.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// HandshakeTimeout bounds the whole CONNECT authentication handshake for a
	// single connection. Defaults to 30s. A shorter deadline on the request
	// context still takes precedence.
	HandshakeTimeout time.Duration

	// MaxLegs caps the number of CONNECT round trips in a single handshake, a
	// safety valve against a misbehaving proxy. Defaults to 10.
	MaxLegs int

	// ForceAttemptHTTP2 mirrors http.Transport.ForceAttemptHTTP2 for origin
	// connections. Defaults to true.
	ForceAttemptHTTP2 *bool
}

// proxyContextKey carries the resolved proxy URL from RoundTrip down into the
// custom DialContext (which only receives the origin address).
type proxyContextKey struct{}

// Transport is an http.RoundTripper that authenticates to a forward proxy using
// Windows SSPI. It is safe for concurrent use by multiple goroutines.
type Transport struct {
	cfg     Config
	schemes []string
	maxLegs int
	hsTO    time.Duration
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)

	// tunneled carries origin traffic through an authenticated CONNECT tunnel.
	tunneled *http.Transport
	// direct carries traffic for hosts that resolve to no proxy.
	direct *http.Transport
}

// New builds a Transport from cfg.
func New(cfg Config) *Transport {
	t := &Transport{cfg: cfg}

	t.schemes = cfg.Schemes
	if len(t.schemes) == 0 {
		t.schemes = []string{"Negotiate", "NTLM"}
	}
	t.maxLegs = cfg.MaxLegs
	if t.maxLegs <= 0 {
		t.maxLegs = 10
	}
	t.hsTO = cfg.HandshakeTimeout
	if t.hsTO <= 0 {
		t.hsTO = 30 * time.Second
	}

	t.dial = cfg.DialContext
	if t.dial == nil {
		d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		t.dial = d.DialContext
	}

	h2 := true
	if cfg.ForceAttemptHTTP2 != nil {
		h2 = *cfg.ForceAttemptHTTP2
	}

	t.tunneled = &http.Transport{
		Proxy:                 nil, // proxying is handled inside dialTunnel
		DialContext:           t.dialTunnel,
		TLSClientConfig:       cfg.TLSClientConfig,
		ForceAttemptHTTP2:     h2,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	t.direct = &http.Transport{
		Proxy:                 nil,
		DialContext:           t.dial,
		TLSClientConfig:       cfg.TLSClientConfig,
		ForceAttemptHTTP2:     h2,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return t
}

// Client is a convenience helper returning an *http.Client that uses this
// Transport.
func (t *Transport) Client() *http.Client {
	return &http.Client{Transport: t}
}

// CloseIdleConnections releases idle connections held by the underlying
// transports.
func (t *Transport) CloseIdleConnections() {
	t.tunneled.CloseIdleConnections()
	t.direct.CloseIdleConnections()
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	proxyURL, err := t.proxyForRequest(req)
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return t.direct.RoundTrip(req)
	}
	ctx := context.WithValue(req.Context(), proxyContextKey{}, proxyURL)
	return t.tunneled.RoundTrip(req.WithContext(ctx))
}

func (t *Transport) proxyForRequest(req *http.Request) (*url.URL, error) {
	switch {
	case t.cfg.Proxy != nil:
		return t.cfg.Proxy(req)
	case t.cfg.ProxyURL != nil:
		return t.cfg.ProxyURL, nil
	default:
		return http.ProxyFromEnvironment(req)
	}
}

// dialTunnel dials the proxy and establishes an authenticated CONNECT tunnel to
// addr (the origin host:port). The returned connection behaves, to the caller,
// as if it were a direct connection to the origin: http.Transport then performs
// the origin TLS handshake over it for https requests, or speaks plaintext HTTP
// over it for http requests.
func (t *Transport) dialTunnel(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyURL, _ := ctx.Value(proxyContextKey{}).(*url.URL)
	if proxyURL == nil {
		// Defensive: should not happen because RoundTrip always sets it.
		return t.dial(ctx, network, addr)
	}

	conn, err := t.dial(ctx, "tcp", proxyAddr(proxyURL))
	if err != nil {
		return nil, fmt.Errorf("proxyauth: dialing proxy %s: %w", proxyURL.Host, err)
	}

	// If the proxy itself is reached over TLS, wrap the connection now.
	if strings.EqualFold(proxyURL.Scheme, "https") {
		tconf := t.cfg.ProxyTLSClientConfig.Clone()
		if tconf == nil {
			tconf = &tls.Config{}
		}
		if tconf.ServerName == "" {
			tconf.ServerName = proxyURL.Hostname()
		}
		tc := tls.Client(conn, tconf)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxyauth: TLS handshake to proxy: %w", err)
		}
		conn = tc
	}

	if err := t.connect(ctx, conn, addr, proxyURL); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// connect performs the (possibly multi-leg) authenticated CONNECT handshake on
// conn. On success the tunnel to targetAddr is open and conn is left ready for
// the caller with all deadlines cleared.
func (t *Transport) connect(ctx context.Context, conn net.Conn, targetAddr string, proxyURL *url.URL) error {
	// Bound the handshake with a deadline, honoring an earlier ctx deadline.
	deadline := time.Now().Add(t.hsTO)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{}) // clear before handing conn back

	br := bufio.NewReader(conn)

	// Leg 0: an unauthenticated CONNECT. If the proxy needs no auth it answers
	// 200 immediately; otherwise it answers 407 and advertises its schemes.
	resp, err := writeConnect(conn, br, targetAddr, "")
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		return &ConnectError{Status: resp.Status, StatusCode: resp.StatusCode}
	}

	challenges := parseProxyAuthenticate(resp.Header)
	scheme := chooseScheme(t.schemes, challenges)
	if scheme == "" {
		return fmt.Errorf("proxyauth: proxy requires authentication but offers no supported scheme (offered: %s, supported: %s)",
			strings.Join(challengeSchemes(challenges), ", "), strings.Join(t.schemes, ", "))
	}
	if !keepAlive(resp) {
		return errors.New("proxyauth: proxy closed the connection before authentication could proceed")
	}

	auth, err := newAuthenticator(scheme, t.spnFor(proxyURL), &t.cfg)
	if err != nil {
		return err
	}
	defer auth.free()

	var input []byte // server token fed into the next SSPI step (nil to start)
	for leg := 0; leg < t.maxLegs; leg++ {
		out, done, err := auth.token(input)
		if err != nil {
			return fmt.Errorf("proxyauth: generating %s token: %w", scheme, err)
		}
		credential := scheme + " " + base64.StdEncoding.EncodeToString(out)

		resp, err = writeConnect(conn, br, targetAddr, credential)
		if err != nil {
			return err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil
		case http.StatusProxyAuthRequired:
			if done {
				return errors.New("proxyauth: proxy rejected authentication (407 after the final token)")
			}
			if !keepAlive(resp) {
				return errors.New("proxyauth: proxy closed the connection mid-handshake")
			}
			input, err = tokenForScheme(resp.Header, scheme)
			if err != nil {
				return err
			}
		default:
			return &ConnectError{Status: resp.Status, StatusCode: resp.StatusCode}
		}
	}
	return fmt.Errorf("proxyauth: authentication did not complete within %d legs", t.maxLegs)
}

func (t *Transport) spnFor(proxyURL *url.URL) string {
	if t.cfg.SPN != "" {
		return t.cfg.SPN
	}
	return "HTTP/" + proxyURL.Hostname()
}

// ConnectError reports a non-200, non-407 response to a CONNECT request.
type ConnectError struct {
	Status     string
	StatusCode int
}

func (e *ConnectError) Error() string {
	return fmt.Sprintf("proxyauth: CONNECT failed: %s", e.Status)
}

// writeConnect writes one CONNECT request (optionally carrying a
// Proxy-Authorization credential) and reads the response, fully draining the
// body so the buffered reader is positioned for the next response on the same
// keep-alive connection.
func writeConnect(conn net.Conn, br *bufio.Reader, targetAddr, credential string) (*http.Response, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		// URL.Opaque makes Request.Write emit the authority-form request-target
		// ("host:port") required for CONNECT.
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: make(http.Header),
	}
	req.Header.Set("Proxy-Connection", "Keep-Alive")
	if credential != "" {
		req.Header.Set("Proxy-Authorization", credential)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("proxyauth: writing CONNECT: %w", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("proxyauth: reading CONNECT response: %w", err)
	}
	// Drain and close so the connection can be reused for the next leg / the
	// tunneled origin traffic.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp, nil
}

// proxyAddr returns host:port for dialing the proxy, supplying a default port
// from the scheme when the URL omits it.
func proxyAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if strings.EqualFold(u.Scheme, "https") {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

// keepAlive reports whether the proxy intends to keep the connection open,
// which is required to continue a multi-leg handshake.
func keepAlive(resp *http.Response) bool {
	if resp.Close {
		return false
	}
	if strings.EqualFold(resp.Header.Get("Proxy-Connection"), "close") {
		return false
	}
	if strings.EqualFold(resp.Header.Get("Connection"), "close") {
		return false
	}
	return true
}

// challenge is one entry parsed from a Proxy-Authenticate header.
type challenge struct {
	scheme string
	token  string // base64 token, if the proxy supplied one inline
}

func parseProxyAuthenticate(h http.Header) []challenge {
	// RFC 7235: Proxy-Authenticate is a comma-separated list of challenges,
	// each "scheme [ SP token ]". We split on commas first, then on the first
	// space, so both "Negotiate, NTLM" (two bare schemes) and "Negotiate <tok>"
	// (one token-bearing challenge) parse correctly. This is safe for the
	// schemes we care about (Negotiate/NTLM/Basic), whose token68 values never
	// contain a comma; it is not a general RFC 7235 parser (e.g. a Digest
	// challenge with comma-separated auth-params would be mis-split).
	var out []challenge
	for _, v := range h.Values("Proxy-Authenticate") {
		for _, seg := range strings.Split(v, ",") {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			if sp := strings.IndexAny(seg, " \t"); sp >= 0 {
				out = append(out, challenge{
					scheme: seg[:sp],
					token:  strings.TrimSpace(seg[sp+1:]),
				})
			} else {
				out = append(out, challenge{scheme: seg})
			}
		}
	}
	return out
}

func challengeSchemes(cs []challenge) []string {
	var s []string
	for _, c := range cs {
		s = append(s, c.scheme)
	}
	return s
}

// chooseScheme returns the first configured scheme that the proxy offered.
func chooseScheme(preferred []string, offered []challenge) string {
	for _, p := range preferred {
		for _, c := range offered {
			if strings.EqualFold(p, c.scheme) {
				return c.scheme // preserve the proxy's casing on the wire
			}
		}
	}
	return ""
}

// tokenForScheme extracts and base64-decodes the continuation token the proxy
// sent for scheme in a 407 response. A missing token decodes to nil, which is a
// valid "no server token" input for the SSPI step.
func tokenForScheme(h http.Header, scheme string) ([]byte, error) {
	for _, c := range parseProxyAuthenticate(h) {
		if strings.EqualFold(c.scheme, scheme) {
			if c.token == "" {
				return nil, nil
			}
			raw, err := base64.StdEncoding.DecodeString(c.token)
			if err != nil {
				return nil, fmt.Errorf("proxyauth: decoding %s token from proxy: %w", scheme, err)
			}
			return raw, nil
		}
	}
	return nil, nil
}
