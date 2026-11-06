// Package vault is a small HashiCorp Vault client for the two things ykgpg
// does with Vault: logging in with a YubiKey certificate, and registering that
// certificate as a cert-auth role. It uses the HTTP API directly so neither
// the vault CLI nor a Vault SDK is needed.
package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultMount is the cert auth mount.
const DefaultMount = "cert"

// Client talks to the Vault HTTP API.
type Client struct {
	Addr  string
	HTTP  *http.Client
	Token string // sent as X-Vault-Token when set
}

// AddrFromEnv returns VAULT_ADDR (empty when unset).
func AddrFromEnv() string { return os.Getenv("VAULT_ADDR") }

// TLSConfig builds the base TLS config, honouring VAULT_CACERT.
func TLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca := os.Getenv("VAULT_CACERT"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("reading VAULT_CACERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("VAULT_CACERT holds no PEM certificates")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// NewClient returns a client with a plain TLS transport (no client cert).
func NewClient(addr, token string) (*Client, error) {
	if addr == "" {
		return nil, errors.New("no Vault address: set VAULT_ADDR or pass --addr")
	}
	tlsCfg, err := TLSConfig()
	if err != nil {
		return nil, err
	}
	return &Client{
		Addr:  strings.TrimRight(addr, "/"),
		Token: token,
		HTTP: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, DisableKeepAlives: true},
		},
	}, nil
}

// apiError is a Vault error response.
type apiError struct {
	Status int
	Errors []string
}

func (e *apiError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, strings.Join(e.Errors, "; "))
}

// IsNotFound reports whether err is a Vault 404.
func IsNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// do sends one request and decodes the JSON reply into out (if non-nil).
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Addr+"/v1/"+strings.TrimLeft(path, "/"), rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &apiError{Status: resp.StatusCode}
		var e struct {
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(raw, &e) == nil {
			ae.Errors = e.Errors
		}
		return ae
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("unreadable Vault response (HTTP %d): %w", resp.StatusCode, err)
	}
	return nil
}

// ResolveToken returns the Vault token from VAULT_TOKEN or ~/.vault-token.
func ResolveToken() (string, error) {
	if t := strings.TrimSpace(os.Getenv("VAULT_TOKEN")); t != "" {
		return t, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(home, ".vault-token"))
	if err != nil {
		return "", errors.New("no Vault token: set VAULT_TOKEN or log in first (ykgpg vault login)")
	}
	if t := strings.TrimSpace(string(b)); t != "" {
		return t, nil
	}
	return "", errors.New("~/.vault-token is empty")
}

// SaveToken writes the token to ~/.vault-token with mode 0600.
func SaveToken(token string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return saveTokenFile(filepath.Join(home, ".vault-token"), token)
}

func saveTokenFile(path, token string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-token-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(token); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func escapeSegment(s string) string { return url.PathEscape(s) }
