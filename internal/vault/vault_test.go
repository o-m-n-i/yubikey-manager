package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bobbydams/yubikey-manager/internal/piv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c, key
}

type fakeCard struct {
	cert        *x509.Certificate
	key         crypto.Signer
	retries     int
	signerCalls int
}

func (f *fakeCard) Certificate() (*x509.Certificate, error) { return f.cert, nil }
func (f *fakeCard) Retries() (int, error)                   { return f.retries, nil }
func (f *fakeCard) Close() error                            { return nil }
func (f *fakeCard) Signer(crypto.PublicKey, func() (string, error)) (crypto.Signer, error) {
	f.signerCalls++
	return f.key, nil
}

// vaultServer is a TLS server that demands a client certificate, like Vault's
// cert listener, and answers the login endpoint.
func vaultServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c := &Client{
		Addr: srv.URL,
		HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
	}
	return srv, c
}

const loginReply = `{"auth":{"client_token":"s.SECRET-TOKEN","policies":["default","yubikey-admin"],"lease_duration":28800,"metadata":{"cert_name":"yubikey-test"}}}`

func TestLoginWithCard_SignsHandshakeAndOmitsRoleName(t *testing.T) {
	cert, key := newCert(t, "yubikey-test")
	var gotCert *x509.Certificate
	var gotBody map[string]string
	var gotPath string
	_, c := vaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			gotCert = r.TLS.PeerCertificates[0]
		}
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = fmt.Fprint(w, loginReply)
	})

	card := &fakeCard{cert: cert, key: key, retries: 3}
	res, err := c.LoginWithCard(context.Background(), card, "cert", "", func(int) (string, error) { return "123456", nil })
	require.NoError(t, err)

	assert.Equal(t, "/v1/auth/cert/login", gotPath)
	require.NotNil(t, gotCert, "server must have received the client certificate")
	assert.Equal(t, cert.Raw, gotCert.Raw)
	assert.NotContains(t, gotBody, "name", "no role name lets Vault pick the matching role")
	assert.Equal(t, "s.SECRET-TOKEN", res.Token)
	assert.Equal(t, []string{"default", "yubikey-admin"}, res.Policies)
	assert.Equal(t, 8*time.Hour, res.TTL)
	assert.Equal(t, "yubikey-test", res.CertName)
}

func TestLoginWithCard_SendsRoleWhenGiven(t *testing.T) {
	cert, key := newCert(t, "x")
	var gotBody map[string]string
	_, c := vaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = fmt.Fprint(w, loginReply)
	})
	_, err := c.LoginWithCard(context.Background(), &fakeCard{cert: cert, key: key, retries: 3}, "cert", "yubikey-test", nil)
	require.NoError(t, err)
	assert.Equal(t, "yubikey-test", gotBody["name"])
}

func TestLoginWithCard_RefusesWithOneAttemptLeft(t *testing.T) {
	cert, key := newCert(t, "x")
	requests := 0
	_, c := vaultServer(t, func(w http.ResponseWriter, r *http.Request) { requests++ })

	for _, retries := range []int{1, 0} {
		card := &fakeCard{cert: cert, key: key, retries: retries}
		_, err := c.LoginWithCard(context.Background(), card, "cert", "", func(int) (string, error) {
			t.Fatal("must not ask for a PIN")
			return "", nil
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not trying")
		assert.Zero(t, card.signerCalls, "the card must not be asked to sign")
	}
	assert.Zero(t, requests)
}

func TestLoginWithCard_VaultRejects(t *testing.T) {
	cert, key := newCert(t, "x")
	_, c := vaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"errors":["invalid certificate or no client certificate supplied"]}`)
	})
	_, err := c.LoginWithCard(context.Background(), &fakeCard{cert: cert, key: key, retries: 3}, "cert", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 400")
	assert.Contains(t, err.Error(), "invalid certificate")
}

func TestLoginResult_NeverFormatsTheToken(t *testing.T) {
	r := LoginResult{Token: "s.SECRET-TOKEN", Policies: []string{"p"}, CertName: "n"}
	for _, s := range []string{fmt.Sprint(r), fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r), r.String()} {
		assert.NotContains(t, s, "SECRET-TOKEN")
	}
}

func rolesServer(t *testing.T, roles map[string]*x509.Certificate) (*Client, *[]map[string]any) {
	t.Helper()
	var writes []map[string]any
	_, c := vaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "admin-token" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		const base = "/v1/auth/cert/certs"
		switch {
		case r.Method == "LIST" && r.URL.Path == base:
			var keys []string
			for n := range roles {
				keys = append(keys, n)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
		case r.Method == http.MethodGet && len(r.URL.Path) > len(base):
			name := r.URL.Path[len(base)+1:]
			ct, ok := roles[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"certificate": pemOf(ct)}})
		case r.Method == http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			body["_path"] = r.URL.Path
			writes = append(writes, body)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	c.Token = "admin-token"
	return c, &writes
}

func pemOf(c *x509.Certificate) string { return pemEncode(c) }

func TestListCertRoles_AndFingerprintMatch(t *testing.T) {
	a, _ := newCert(t, "a")
	b, _ := newCert(t, "b")
	c, writes := rolesServer(t, map[string]*x509.Certificate{"yubikey-a": a, "yubikey-b": b})
	_ = writes

	roles, err := c.ListCertRoles(context.Background())
	require.NoError(t, err)
	require.Len(t, roles, 2)

	assert.Equal(t, []string{"yubikey-a"}, RolesWithFingerprint(roles, piv.Fingerprint(a)))
	assert.Equal(t, []string{"yubikey-b"}, RolesWithFingerprint(roles, piv.Fingerprint(b)))
	other, _ := newCert(t, "other")
	assert.Empty(t, RolesWithFingerprint(roles, piv.Fingerprint(other)))
}

func TestListCertRoles_NoRolesYet(t *testing.T) {
	_, c := vaultServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	roles, err := c.ListCertRoles(context.Background())
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestListCertRoles_PermissionDenied(t *testing.T) {
	c, _ := rolesServer(t, nil)
	c.Token = "wrong"
	_, err := c.ListCertRoles(context.Background())
	assert.ErrorContains(t, err, "permission denied")
}

func TestRegisterCert_WritesRoleSettings(t *testing.T) {
	ct, _ := newCert(t, "yubikey-laptop-a")
	c, writes := rolesServer(t, nil)

	require.NoError(t, c.RegisterCert(context.Background(), "yubikey-laptop-a", ct))
	require.Len(t, *writes, 1)
	w := (*writes)[0]
	assert.Equal(t, "/v1/auth/cert/certs/yubikey-laptop-a", w["_path"])
	assert.Equal(t, "yubikey-admin", w["token_policies"])
	assert.Equal(t, "8h", w["token_ttl"])
	assert.Equal(t, "24h", w["token_max_ttl"])
	assert.Equal(t, pemOf(ct), w["certificate"])
}

func TestSaveToken_Mode0600AndOverwritesWiderMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".vault-token")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

	require.NoError(t, saveTokenFile(path, "new-token"))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	b, _ := os.ReadFile(path)
	assert.Equal(t, "new-token", string(b))
}

func TestResolveToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Setenv("VAULT_TOKEN", "")
	_, err := ResolveToken()
	assert.Error(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(home, ".vault-token"), []byte("file-token\n"), 0o600))
	got, err := ResolveToken()
	require.NoError(t, err)
	assert.Equal(t, "file-token", got)

	t.Setenv("VAULT_TOKEN", "env-token")
	got, _ = ResolveToken()
	assert.Equal(t, "env-token", got)
}

func TestTLSConfig_BadCACert(t *testing.T) {
	f := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(f, []byte("not pem"), 0o600))
	t.Setenv("VAULT_CACERT", f)
	_, err := TLSConfig()
	assert.ErrorContains(t, err, "no PEM")

	t.Setenv("VAULT_CACERT", filepath.Join(t.TempDir(), "missing"))
	_, err = TLSConfig()
	assert.Error(t, err)
}
