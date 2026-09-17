//go:build !windows

package proxyauth

// newAuthenticator is a stub on non-Windows platforms. The package still
// compiles and its non-authenticating paths (proxy discovery, direct dialing,
// header parsing, unauthenticated CONNECT) work, but a proxy that actually
// requires SSPI authentication yields ErrUnsupportedPlatform.
func newAuthenticator(scheme, spn string, cfg *Config) (authenticator, error) {
	return nil, ErrUnsupportedPlatform
}
