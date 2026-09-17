// Package proxyauth provides an http.RoundTripper that transparently
// authenticates to an HTTP(S) forward proxy that answers with
// "407 Proxy Authentication Required" using the Windows-native
// Negotiate (SPNEGO/Kerberos) or NTLM schemes.
//
// # Why this package exists
//
// Go's standard net/http can only preload "Proxy-Authorization: Basic ..."
// from credentials embedded in the proxy URL. It has no understanding of the
// connection-oriented Negotiate/NTLM schemes, and for HTTPS requests the proxy
// authentication happens during the CONNECT tunnel setup, where a 407 is
// surfaced as an error from RoundTrip rather than as a response you can inspect
// and retry. Worse, NTLM (and SPNEGO's NTLM fallback) is a multi-leg handshake
// that must complete on a single, kept-alive TCP connection to the proxy —
// something http.Transport's CONNECT handling cannot do.
//
// This package solves that by taking over the CONNECT tunnel: it dials the
// proxy itself, runs the full multi-leg SSPI handshake on that one connection,
// and only then hands the established tunnel back to an http.Transport, which
// performs TLS to the origin over it. Because it uses SSPI, it authenticates
// with the credentials of the currently logged-in Windows user (single
// sign-on) — no keytab, no stored password — or with an explicit
// domain/user/password if you provide one.
//
// # Platform support
//
// The SSPI machinery is Windows-only. The package compiles on every platform so
// you can build and unit-test cross-platform, but on non-Windows a proxy that
// actually requires authentication yields ErrUnsupportedPlatform.
//
// Basic usage
//
//	rt := proxyauth.New(proxyauth.Config{}) // proxy from HTTPS_PROXY / HTTP_PROXY
//	client := &http.Client{Transport: rt, Timeout: 30 * time.Second}
//	resp, err := client.Get("https://internal.example.com/api")
//
// See Config for all knobs (explicit proxy, SPN override, explicit credentials,
// scheme preference, etc.).
package proxyauth
