package vault

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bobbydams/yubikey-manager/internal/piv"
)

// LoginResult is what a successful cert login yields. Token is a secret:
// callers must not print it unless the user asked for it.
type LoginResult struct {
	Token    string
	Policies []string
	TTL      time.Duration
	CertName string
}

// String never includes the token.
func (r LoginResult) String() string {
	return fmt.Sprintf("role %q, policies %v, TTL %s", r.CertName, r.Policies, r.TTL)
}

// GoString never includes the token either (%#v).
func (r LoginResult) GoString() string { return r.String() }

// MinPINAttempts is the number of PIN attempts that must remain before a
// login tries a PIN. One left means a typo locks the PIV application.
const MinPINAttempts = 2

// LoginWithCard logs in with the certificate in slot 9a of an open card.
// The TLS client handshake is signed on the YubiKey. role may be empty, in
// which case Vault picks the role whose certificate matches.
func (c *Client) LoginWithCard(ctx context.Context, card piv.Card, mount, role string, askPIN func(retries int) (string, error)) (*LoginResult, error) {
	cert, err := card.Certificate()
	if err != nil {
		return nil, fmt.Errorf("reading the certificate in slot 9a: %w", err)
	}
	retries, err := card.Retries()
	if err != nil {
		return nil, fmt.Errorf("reading PIN retries: %w", err)
	}
	if retries < MinPINAttempts {
		return nil, fmt.Errorf("only %d PIV PIN attempt(s) left; not trying, to avoid locking the PIV applet (unblock with the PUK: ykman piv access unblock-pin)", retries)
	}
	signer, err := card.Signer(cert.PublicKey, func() (string, error) { return askPIN(retries) })
	if err != nil {
		return nil, fmt.Errorf("opening the slot 9a key: %w", err)
	}
	return c.loginWithCertificate(ctx, cert, signer, mount, role)
}

func (c *Client) loginWithCertificate(ctx context.Context, cert *x509.Certificate, signer crypto.Signer, mount, role string) (*LoginResult, error) {
	// Install the client certificate on a copy of the transport.
	tr, ok := c.HTTP.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("unsupported HTTP transport")
	}
	tr = tr.Clone()
	cfg := tr.TLSClientConfig.Clone()
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: signer, Leaf: cert}, nil
	}
	tr.TLSClientConfig = cfg
	tr.DisableKeepAlives = true
	lc := &Client{Addr: c.Addr, HTTP: &http.Client{Timeout: 60 * time.Second, Transport: tr}}

	body := map[string]string{}
	if role != "" {
		body["name"] = role
	}
	var out struct {
		Auth *struct {
			ClientToken   string            `json:"client_token"`
			Policies      []string          `json:"policies"`
			LeaseDuration int               `json:"lease_duration"`
			Metadata      map[string]string `json:"metadata"`
		} `json:"auth"`
	}
	if err := lc.do(ctx, http.MethodPost, "auth/"+strings.Trim(mount, "/")+"/login", body, &out); err != nil {
		return nil, fmt.Errorf("login request: %w", err)
	}
	if out.Auth == nil || out.Auth.ClientToken == "" {
		return nil, errors.New("login request: Vault returned no token")
	}
	return &LoginResult{
		Token:    out.Auth.ClientToken,
		Policies: out.Auth.Policies,
		TTL:      time.Duration(out.Auth.LeaseDuration) * time.Second,
		CertName: out.Auth.Metadata["cert_name"],
	}, nil
}
