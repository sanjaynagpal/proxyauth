# proxyauth

A Go `http.RoundTripper` that transparently authenticates to a corporate
forward proxy which challenges with **`407 Proxy Authentication Required`**,
using the Windows-native **Negotiate (SPNEGO/Kerberos)** or **NTLM** schemes and
the **logged-in user's credentials** (single sign-on).

Built for the HTTPS case: proxy authentication happens inside the `CONNECT`
tunnel, and NTLM / SPNEGO-NTLM is a multi-leg handshake that must complete on a
single kept-alive connection — neither of which Go's standard `net/http` can do.

## Why the standard library isn't enough

- `net/http` only knows how to preload `Proxy-Authorization: Basic …` from
  credentials in the proxy URL. It has **no** support for `Negotiate`/`NTLM`.
- For an **HTTPS** request the 407 arrives during `CONNECT`, so it surfaces as an
  **error from `RoundTrip`**, not a response you can inspect and retry.
- `Negotiate`/`NTLM` authenticate the **TCP connection**, and NTLM needs three
  messages (Type 1 → Type 2 → Type 3) exchanged on that **same** connection.
  `http.Transport`'s built-in CONNECT handling tears the connection down on a
  non-200 and cannot drive the back-and-forth.

This package takes over the tunnel: it dials the proxy itself, runs the full
multi-leg SSPI handshake on one connection, then hands the established tunnel
back to an `http.Transport`, which performs the origin TLS handshake over it.

## Install

```sh
go get github.com/sanjaynagpal/proxyauth
```

The only dependency is
[`github.com/alexbrainman/sspi`](https://github.com/alexbrainman/sspi).

## Usage

```go
import "github.com/sanjaynagpal/proxyauth"

// Proxy discovered from HTTPS_PROXY / HTTP_PROXY / NO_PROXY,
// authenticating as the logged-in Windows user:
client := &http.Client{
    Transport: proxyauth.New(proxyauth.Config{}),
    Timeout:   30 * time.Second,
}
resp, err := client.Get("https://internal.example.com/api")
```

Explicit proxy and/or explicit credentials:

```go
u, _ := url.Parse("http://proxy.corp.example:8080")
rt := proxyauth.New(proxyauth.Config{
    ProxyURL: u,
    // Omit these three to use the logged-in user (SSO), which is the usual case:
    Domain:   "CORP",
    Username: "svc-app",
    Password: os.Getenv("SVC_APP_PASSWORD"),
    // SPN defaults to "HTTP/<proxy-host>"; override if your Kerberos SPN differs:
    // SPN: "HTTP/proxy.corp.example",
})
```

`Config` also exposes `Schemes` (preference order, default
`{"Negotiate","NTLM"}`), `TLSClientConfig` (origin TLS), `ProxyTLSClientConfig`
(when the proxy itself is reached over HTTPS), `DialContext`, `HandshakeTimeout`,
and `MaxLegs`. See `doc.go` / GoDoc for the full list.

## How a request flows

1. `RoundTrip` resolves the proxy for the request (`Config.Proxy` →
   `Config.ProxyURL` → environment). No proxy ⇒ the request is dialed directly.
2. For a proxied request the custom dialer opens a TCP connection to the proxy
   (upgrading to TLS first if the proxy URL is `https`).
3. It sends an unauthenticated `CONNECT`. A `200` means no auth is needed; a
   `407` advertises the proxy's schemes.
4. It picks the best offered scheme it supports and runs the SSPI handshake,
   sending each generated token in `Proxy-Authorization` and feeding the
   proxy's `Proxy-Authenticate` continuation token back into SSPI, all on the
   same connection, until the proxy returns `200`.
5. The now-authenticated tunnel is handed to `http.Transport`, which does the
   origin TLS handshake and the actual HTTP request over it. Pooled connections
   reuse the already-authenticated tunnel.

## Platform support

The SSPI machinery is **Windows-only**. The package compiles on every platform
(so you can build and unit-test in CI on Linux/macOS), but at runtime on a
non-Windows OS a proxy that actually requires authentication returns
`proxyauth.ErrUnsupportedPlatform`. The parsing/transport logic is covered by
platform-independent tests (`go test ./...`).

## Notes and limitations

- **HTTP (plaintext) origins** are also routed through a `CONNECT` tunnel
  (to `origin:80`), so the same connection-oriented auth works for them. A proxy
  that forbids `CONNECT` to port 80 would reject those; HTTPS is unaffected.
- **Kerberos** needs a correct SPN (`HTTP/<proxy-fqdn>`) and a reachable KDC;
  when Kerberos isn't available, SPNEGO falls back to NTLM automatically.
- The header parser targets `Negotiate`/`NTLM`/`Basic`; it is not a full
  RFC 7235 parser (a `Digest` challenge with comma-separated params could be
  mis-split).
- Credentials come from Windows SSPI; no password is stored or transmitted when
  using the default SSO path.

## Development

```sh
go test ./...                      # logic/parsing tests (any OS)
GOOS=windows go build ./...        # verify the SSPI path compiles
```
