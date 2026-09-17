package proxyauth

// authenticator is one client-side SSPI security context driving a single
// proxy-authentication handshake. token is called once per leg: the first call
// receives a nil input and returns the initial client token; subsequent calls
// receive the server's continuation token (from Proxy-Authenticate) and return
// the next client token. done reports that the client considers the handshake
// finished after the returned token is sent.
type authenticator interface {
	token(input []byte) (out []byte, done bool, err error)
	free()
}

// newAuthenticator is implemented per platform: SSPI on Windows
// (auth_windows.go), a stub returning ErrUnsupportedPlatform elsewhere
// (auth_stub.go).
