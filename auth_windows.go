//go:build windows

package proxyauth

import (
	"fmt"
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/alexbrainman/sspi/ntlm"
)

// newAuthenticator creates an SSPI-backed authenticator for the chosen scheme.
func newAuthenticator(scheme, spn string, cfg *Config) (authenticator, error) {
	switch strings.ToLower(scheme) {
	case "negotiate":
		return newNegotiateAuth(spn, cfg)
	case "ntlm":
		return newNTLMAuth(cfg)
	default:
		return nil, fmt.Errorf("proxyauth: unsupported scheme %q", scheme)
	}
}

// --- Negotiate (SPNEGO: Kerberos, with automatic NTLM fallback) ---

type negotiateAuth struct {
	cred *sspi.Credentials
	cc   *negotiate.ClientContext
	spn  string
}

func newNegotiateAuth(spn string, cfg *Config) (*negotiateAuth, error) {
	cred, err := acquireCredentials(
		negotiate.AcquireCurrentUserCredentials,
		negotiate.AcquireUserCredentials,
		cfg,
	)
	if err != nil {
		return nil, fmt.Errorf("proxyauth: acquiring Negotiate credentials: %w", err)
	}
	return &negotiateAuth{cred: cred, spn: spn}, nil
}

func (a *negotiateAuth) token(input []byte) (out []byte, done bool, err error) {
	if a.cc == nil {
		// First leg: create the security context and emit the initial token
		// (a Kerberos AP-REQ, or an NTLM Type 1 message under SPNEGO).
		a.cc, out, err = negotiate.NewClientContext(a.cred, a.spn)
		if err != nil {
			return nil, false, err
		}
		return out, false, nil
	}
	// Continuation leg: process the server token and emit the next one.
	done, out, err = a.cc.Update(input)
	return out, done, err
}

func (a *negotiateAuth) free() {
	if a.cc != nil {
		_ = a.cc.Release()
		a.cc = nil
	}
	if a.cred != nil {
		_ = a.cred.Release()
		a.cred = nil
	}
}

// --- NTLM (for proxies that offer only the NTLM scheme) ---

type ntlmAuth struct {
	cred *sspi.Credentials
	cc   *ntlm.ClientContext
}

func newNTLMAuth(cfg *Config) (*ntlmAuth, error) {
	cred, err := acquireCredentials(
		ntlm.AcquireCurrentUserCredentials,
		ntlm.AcquireUserCredentials,
		cfg,
	)
	if err != nil {
		return nil, fmt.Errorf("proxyauth: acquiring NTLM credentials: %w", err)
	}
	return &ntlmAuth{cred: cred}, nil
}

func (a *ntlmAuth) token(input []byte) (out []byte, done bool, err error) {
	if a.cc == nil {
		// First leg: emit the NTLM Type 1 (negotiate) message.
		a.cc, out, err = ntlm.NewClientContext(a.cred)
		if err != nil {
			return nil, false, err
		}
		return out, false, nil
	}
	// Second leg: input is the Type 2 challenge; produce the Type 3
	// authenticate message. NTLM completes after Type 3.
	out, err = a.cc.Update(input)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func (a *ntlmAuth) free() {
	if a.cc != nil {
		_ = a.cc.Release()
		a.cc = nil
	}
	if a.cred != nil {
		_ = a.cred.Release()
		a.cred = nil
	}
}

// acquireCredentials returns the logged-in user's credentials (SSO) when no
// explicit username is configured, otherwise builds credentials from the
// configured domain/username/password. The two acquisition functions have the
// same signatures in both the negotiate and ntlm packages, so callers pass the
// package-specific pair.
func acquireCredentials(
	current func() (*sspi.Credentials, error),
	explicit func(domain, username, password string) (*sspi.Credentials, error),
	cfg *Config,
) (*sspi.Credentials, error) {
	if cfg.Username != "" {
		return explicit(cfg.Domain, cfg.Username, cfg.Password)
	}
	return current()
}
