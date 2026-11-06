package cli

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bobbydams/yubikey-manager/internal/executor"
	"github.com/bobbydams/yubikey-manager/internal/piv"
	"github.com/bobbydams/yubikey-manager/internal/vault"
	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	infoBlank = `PIV version:              5.7.1
PIN tries remaining:      3/3
PUK tries remaining:      3/3
Management key algorithm: TDES
WARNING: Using default PIN!
WARNING: Using default PUK!
WARNING: Using default Management key!
CHUID:                    No data available
`
	infoMain = `PIV version:              5.7.1
PIN tries remaining:      3/3
PUK tries remaining:      3/3
Management key algorithm: AES192
Management key is stored on the YubiKey, protected by PIN.
Slot 9A (AUTHENTICATION):
  Private key type: ECCP256
  Public key type:  ECCP256
  Subject DN:       CN=Example PIV Authentication
  Issuer DN:        CN=Example PIV Authentication
  Not before:       2024-01-01T00:00:00+00:00
  Not after:        2054-01-01T00:00:00+00:00
`
	keyInfo = `Key slot:               9A (AUTHENTICATION)
Algorithm:              ECCP256
Origin:                 GENERATED
PIN required for use:   ONCE
Touch required for use: NEVER
`
)

func infoOurs(defaults bool) string {
	s := `PIV version:              5.7.1
PIN tries remaining:      3/3
PUK tries remaining:      3/3
Management key algorithm: TDES
`
	if defaults {
		s += "WARNING: Using default PIN!\nWARNING: Using default PUK!\nWARNING: Using default Management key!\n"
	} else {
		s = strings.Replace(s, "TDES\n", "AES192\nManagement key is stored on the YubiKey, protected by PIN.\n", 1)
	}
	return s + `Slot 9A (AUTHENTICATION):
  Private key type: ECCP256
  Subject DN:       CN=yubikey-laptop-a
  Not after:        2036-11-06T00:00:00+00:00
`
}

func testCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// capture runs fn and returns what it wrote to stdout and stderr.
func capture(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	ui.SetColorEnabled(false)
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	done := make(chan [2]string)
	go func() {
		a, _ := io.ReadAll(ro)
		b, _ := io.ReadAll(re)
		done <- [2]string{string(a), string(b)}
	}()
	func() {
		defer func() { os.Stdout, os.Stderr = oldOut, oldErr; _ = wo.Close(); _ = we.Close() }()
		fn()
	}()
	out := <-done
	return out[0], out[1]
}

func devCmd(device string) *cobra.Command {
	c := &cobra.Command{Use: "x"}
	c.Flags().String("device", device, "")
	c.SetContext(context.Background())
	return c
}

func newTestPivEnv(m *executor.MockExecutor) *pivEnv {
	return &pivEnv{
		exec:         m,
		ykman:        piv.NewYkman(m),
		confirm:      func(string) bool { return true },
		prompt:       func(string) (string, error) { return "", nil },
		mkTempDir:    func() (string, error) { return os.MkdirTemp("", "ykgpg-test-") },
		out:          &strings.Builder{},
		resolveToken: func() (string, error) { return "admin-token", nil },
	}
}

func interactiveSteps(m *executor.MockExecutor) []string {
	var steps []string
	for _, c := range m.InteractiveCalls {
		steps = append(steps, strings.Join(c.Args[2:], " "))
	}
	return steps
}

func TestSetup_BlankKeyRunsAllSteps(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoBlank))

	var err error
	capture(t, func() { err = runPivSetup(devCmd(""), newTestPivEnv(m), "laptop-a", false) })
	require.NoError(t, err)

	steps := interactiveSteps(m)
	require.Len(t, steps, 5)
	assert.Contains(t, steps[0], "piv keys generate -a ECCP256 --pin-policy ONCE --touch-policy ALWAYS 9a")
	assert.Contains(t, steps[1], "piv certificates generate -s CN=yubikey-laptop-a -d 3650 9a")
	assert.Equal(t, "piv access change-pin", steps[2])
	assert.Equal(t, "piv access change-puk", steps[3])
	assert.Equal(t, "piv access change-management-key -a AES192 --generate --protect", steps[4])
}

func TestSetup_RefusesOccupiedSlotWithoutForce(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("11111111\n"))
	m.SetOutput("ykman --device 11111111 piv info", []byte(infoMain))

	var err error
	capture(t, func() { err = runPivSetup(devCmd(""), newTestPivEnv(m), "main", false) })
	require.Error(t, err)
	for _, want := range []string{"11111111", "macOS", "yubikey-agent", "Vault", "--force"} {
		assert.Contains(t, err.Error(), want)
	}
	assert.Empty(t, m.InteractiveCalls, "nothing may be written")
}

func TestSetup_ForceNeedsTheSerialTyped(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("11111111\n"))
	m.SetOutput("ykman --device 11111111 piv info", []byte(infoMain))
	env := newTestPivEnv(m)

	env.prompt = func(string) (string, error) { return "yes", nil }
	var err error
	capture(t, func() { err = runPivSetup(devCmd(""), env, "main", true) })
	require.ErrorContains(t, err, "aborted")
	assert.Empty(t, m.InteractiveCalls)

	env.prompt = func(string) (string, error) { return "11111111", nil }
	capture(t, func() { err = runPivSetup(devCmd(""), env, "main", true) })
	require.NoError(t, err)
	assert.Contains(t, interactiveSteps(m)[0], "piv keys generate")
}

func TestSetup_ResumesOwnKeyWithoutRegenerating(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoOurs(true)))

	var err error
	capture(t, func() { err = runPivSetup(devCmd(""), newTestPivEnv(m), "laptop-a", false) })
	require.NoError(t, err)
	assert.Equal(t, []string{"piv access change-pin", "piv access change-puk",
		"piv access change-management-key -a AES192 --generate --protect"}, interactiveSteps(m))
}

func TestSetup_OtherNameOnOccupiedSlotIsStillRefused(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoOurs(true)))

	var err error
	capture(t, func() { err = runPivSetup(devCmd(""), newTestPivEnv(m), "different", false) })
	require.Error(t, err)
	assert.Empty(t, m.InteractiveCalls)
}

func TestSetup_AlreadyDoneIsANoop(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoOurs(false)))

	var err error
	capture(t, func() { err = runPivSetup(devCmd(""), newTestPivEnv(m), "laptop-a", false) })
	require.NoError(t, err)
	assert.Empty(t, m.InteractiveCalls)
}

func TestSetup_DeclinedConfirmationChangesNothing(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoBlank))
	env := newTestPivEnv(m)
	env.confirm = func(string) bool { return false }

	var err error
	capture(t, func() { err = runPivSetup(devCmd(""), env, "laptop-a", false) })
	require.ErrorContains(t, err, "aborted")
	assert.Empty(t, m.InteractiveCalls)
}

func TestCommands_RefuseWhenSeveralKeysAndNoDevice(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("11111111\n22222222\n"))

	var setupErr, regErr error
	capture(t, func() {
		setupErr = runPivSetup(devCmd(""), newTestPivEnv(m), "x", false)
		regErr = runPivRegister(devCmd(""), newTestPivEnv(m), "x")
	})
	assert.ErrorContains(t, setupErr, "--device")
	assert.ErrorContains(t, regErr, "--device")
	assert.Empty(t, m.InteractiveCalls)
	for _, c := range m.Calls {
		assert.NotContains(t, c.Args, "info", "no per-key command may run before a key is chosen")
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"laptop-a", "laptop-b", "a1"} {
		assert.NoError(t, validateName(ok), ok)
	}
	for _, bad := range []string{"", "UPPER", "under_score", "-x", "x-", "a--b", "a b"} {
		assert.Error(t, validateName(bad), bad)
	}
}

// vaultFake is an admin-token Vault with a mutable set of cert roles.
type vaultFake struct {
	roles  map[string]string // name -> PEM
	writes []string
}

func (f *vaultFake) start(t *testing.T) *vault.Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const base = "/v1/auth/cert/certs"
		switch {
		case r.Method == "LIST" && r.URL.Path == base:
			var keys []string
			for n := range f.roles {
				keys = append(keys, n)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"/"):
			name := strings.TrimPrefix(r.URL.Path, base+"/")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"certificate": f.roles[name]}})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, base+"/"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			name := strings.TrimPrefix(r.URL.Path, base+"/")
			f.writes = append(f.writes, name)
			f.roles[name] = body["certificate"].(string)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &vault.Client{Addr: srv.URL, HTTP: srv.Client(), Token: "admin-token"}
}

func registerEnv(m *executor.MockExecutor, c *vault.Client) *pivEnv {
	env := newTestPivEnv(m)
	env.newVault = func(string) (*vault.Client, error) { return c, nil }
	return env
}

func TestRegister_WritesRoleAndVerifies(t *testing.T) {
	cert, _, pemText := testCert(t, "yubikey-laptop-a")
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoOurs(false)))
	m.SetOutput("ykman --device 22222222 piv certificates export 9a -", []byte(pemText))
	fake := &vaultFake{roles: map[string]string{}}

	var err error
	capture(t, func() { err = runPivRegister(devCmd(""), registerEnv(m, fake.start(t)), "laptop-a") })
	require.NoError(t, err)
	assert.Equal(t, []string{"yubikey-laptop-a"}, fake.writes)
	assert.Equal(t, piv.Fingerprint(cert), fingerprintOfPEM(t, fake.roles["yubikey-laptop-a"]))
}

func fingerprintOfPEM(t *testing.T, p string) string {
	t.Helper()
	cs, err := piv.ParseCertificatesPEM([]byte(p))
	require.NoError(t, err)
	return piv.Fingerprint(cs[0])
}

func TestRegister_RefusesDuplicateCertificate(t *testing.T) {
	_, _, pemText := testCert(t, "yubikey-laptop-a")
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoOurs(false)))
	m.SetOutput("ykman --device 22222222 piv certificates export 9a -", []byte(pemText))
	fake := &vaultFake{roles: map[string]string{"yubikey-old-name": pemText}}

	var err error
	capture(t, func() { err = runPivRegister(devCmd(""), registerEnv(m, fake.start(t)), "laptop-a") })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered as yubikey-old-name")
	assert.Empty(t, fake.writes)
}

func TestRegister_RefusesTakenRoleName(t *testing.T) {
	_, _, pemText := testCert(t, "yubikey-laptop-a")
	_, _, otherPEM := testCert(t, "someone-else")
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoOurs(false)))
	m.SetOutput("ykman --device 22222222 piv certificates export 9a -", []byte(pemText))
	fake := &vaultFake{roles: map[string]string{"yubikey-laptop-a": otherPEM}}

	var err error
	capture(t, func() { err = runPivRegister(devCmd(""), registerEnv(m, fake.start(t)), "laptop-a") })
	require.ErrorContains(t, err, "already exists with a different certificate")
	assert.Empty(t, fake.writes)
}

func TestRegister_NeedsCertificateAndToken(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoBlank))
	var err error
	capture(t, func() { err = runPivRegister(devCmd(""), newTestPivEnv(m), "x") })
	assert.ErrorContains(t, err, "piv setup")

	_, _, pemText := testCert(t, "c")
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoOurs(false)))
	m.SetOutput("ykman --device 22222222 piv certificates export 9a -", []byte(pemText))
	env := newTestPivEnv(m)
	env.resolveToken = func() (string, error) { return "", fmt.Errorf("no Vault token") }
	capture(t, func() { err = runPivRegister(devCmd(""), env, "x") })
	assert.ErrorContains(t, err, "no Vault token")
}

func TestStatus_ShowsDefaultsAndVaultRegistration(t *testing.T) {
	_, _, pemText := testCert(t, "Example PIV Authentication")
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("11111111\n22222222\n"))
	m.SetOutput("ykman --device 11111111 piv info", []byte(infoMain))
	m.SetOutput("ykman --device 11111111 piv keys info 9a", []byte(keyInfo))
	m.SetOutput("ykman --device 11111111 piv certificates export 9a -", []byte(pemText))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoBlank))
	fake := &vaultFake{roles: map[string]string{"yubikey-laptop-b": pemText}}

	var err error
	env := registerEnv(m, fake.start(t))
	capture(t, func() { err = runPivStatus(devCmd(""), env, false) })
	require.NoError(t, err)
	out := env.out.(*strings.Builder).String()

	assert.Contains(t, out, "YUBIKEY 11111111")
	assert.Contains(t, out, "YUBIKEY 22222222")
	assert.Contains(t, out, "ECCP256, PIN once, touch never")
	assert.Contains(t, out, "CN=Example PIV Authentication")
	assert.Contains(t, out, "registered as yubikey-laptop-b")
	assert.Contains(t, out, "factory default")
	assert.Contains(t, out, "empty")
	assert.Empty(t, m.InteractiveCalls)
}

func TestStatus_VaultUnreachableIsNotFatal(t *testing.T) {
	_, _, pemText := testCert(t, "c")
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("11111111\n"))
	m.SetOutput("ykman --device 11111111 piv info", []byte(infoMain))
	m.SetOutput("ykman --device 11111111 piv keys info 9a", []byte(keyInfo))
	m.SetOutput("ykman --device 11111111 piv certificates export 9a -", []byte(pemText))
	env := newTestPivEnv(m)
	env.resolveToken = func() (string, error) { return "", fmt.Errorf("no Vault token") }

	var err error
	capture(t, func() { err = runPivStatus(devCmd(""), env, false) })
	require.NoError(t, err)
	assert.Contains(t, env.out.(*strings.Builder).String(), "unknown (no Vault token)")
}

func TestStatus_DeviceFilter(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("11111111\n22222222\n"))
	m.SetOutput("ykman --device 22222222 piv info", []byte(infoBlank))

	var err error
	env := newTestPivEnv(m)
	capture(t, func() { err = runPivStatus(devCmd("22222222"), env, true) })
	require.NoError(t, err)
	out := env.out.(*strings.Builder).String()
	assert.Contains(t, out, "YUBIKEY 22222222")
	assert.NotContains(t, out, "11111111")
}

// ---- vault login ----

type fakeCard struct {
	cert    *x509.Certificate
	key     crypto.Signer
	retries int
	signed  bool
}

func (f *fakeCard) Certificate() (*x509.Certificate, error) { return f.cert, nil }
func (f *fakeCard) Retries() (int, error)                   { return f.retries, nil }
func (f *fakeCard) Close() error                            { return nil }
func (f *fakeCard) Signer(crypto.PublicKey, func() (string, error)) (crypto.Signer, error) {
	f.signed = true
	return f.key, nil
}

const secretToken = "s.TOP-SECRET-TOKEN"

func loginTestEnv(t *testing.T, card *fakeCard, serials []string) (*loginEnv, *executor.MockExecutor, *string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"auth":{"client_token":%q,"policies":["default","yubikey-admin"],"lease_duration":28800,"metadata":{"cert_name":"yubikey-laptop-a"}}}`, secretToken)
	}))
	t.Cleanup(srv.Close)
	m := executor.NewMockExecutor()
	saved := ""
	return &loginEnv{
		exec:        m,
		listSerials: func() ([]string, error) { return serials, nil },
		openCard:    func(string) (piv.Card, error) { return card, nil },
		newVault:    func(string) (*vault.Client, error) { return &vault.Client{Addr: srv.URL, HTTP: srv.Client()}, nil },
		askPIN:      func(int) (string, error) { return "123456", nil },
		saveToken:   func(tok string) error { saved = tok; return nil },
	}, m, &saved
}

func TestVaultLogin_NeverPrintsTheTokenByDefault(t *testing.T) {
	cert, key, _ := testCert(t, "c")
	card := &fakeCard{cert: cert, key: key, retries: 3}
	env, m, saved := loginTestEnv(t, card, []string{"22222222"})

	var err error
	out, errOut := capture(t, func() { err = runVaultLogin(devCmd(""), env, loginOpts{addr: "https://vault.example", mount: "cert"}) })
	require.NoError(t, err)

	assert.Equal(t, secretToken, *saved)
	assert.NotContains(t, out+errOut, secretToken)
	assert.NotContains(t, out+errOut, "TOP-SECRET")
	assert.Contains(t, out, `cert role "yubikey-laptop-a"`)
	assert.Contains(t, out, "yubikey-admin")
	assert.Contains(t, out, "8h0m0s")
	assert.True(t, m.VerifyCall("gpgconf", "--kill", "scdaemon"), "scdaemon must be released before the card is opened")
}

func TestVaultLogin_PrintTokenOnlyOnRequest(t *testing.T) {
	cert, key, _ := testCert(t, "c")
	env, _, _ := loginTestEnv(t, &fakeCard{cert: cert, key: key, retries: 3}, []string{"1"})

	var err error
	out, _ := capture(t, func() { err = runVaultLogin(devCmd(""), env, loginOpts{mount: "cert", printToken: true, noSave: true}) })
	require.NoError(t, err)
	assert.Contains(t, out, "export VAULT_TOKEN='"+secretToken+"'")
}

func TestVaultLogin_NoSave(t *testing.T) {
	cert, key, _ := testCert(t, "c")
	env, _, saved := loginTestEnv(t, &fakeCard{cert: cert, key: key, retries: 3}, []string{"1"})

	capture(t, func() { _ = runVaultLogin(devCmd(""), env, loginOpts{mount: "cert", noSave: true}) })
	assert.Empty(t, *saved)
}

func TestVaultLogin_RefusesWithOneAttemptLeft(t *testing.T) {
	cert, key, _ := testCert(t, "c")
	card := &fakeCard{cert: cert, key: key, retries: 1}
	env, _, saved := loginTestEnv(t, card, []string{"1"})
	env.askPIN = func(int) (string, error) { t.Fatal("must not ask for a PIN"); return "", nil }

	var err error
	capture(t, func() { err = runVaultLogin(devCmd(""), env, loginOpts{mount: "cert"}) })
	require.ErrorContains(t, err, "attempt")
	assert.False(t, card.signed)
	assert.Empty(t, *saved)
}

func TestVaultLogin_SeveralKeysNeedDevice(t *testing.T) {
	cert, key, _ := testCert(t, "c")
	env, _, _ := loginTestEnv(t, &fakeCard{cert: cert, key: key, retries: 3}, []string{"1", "2"})
	env.openCard = func(string) (piv.Card, error) { t.Fatal("must not open any card"); return nil, nil }

	var err error
	capture(t, func() { err = runVaultLogin(devCmd(""), env, loginOpts{mount: "cert"}) })
	assert.ErrorContains(t, err, "--device")

	opened := ""
	env.openCard = func(s string) (piv.Card, error) { opened = s; return &fakeCard{cert: cert, key: key, retries: 3}, nil }
	capture(t, func() { err = runVaultLogin(devCmd(""), env, loginOpts{mount: "cert", noSave: true, device: "2"}) })
	require.NoError(t, err)
	assert.Equal(t, "2", opened)
}

func TestVaultLogin_YubikeyAgentIsReportedNotKilled(t *testing.T) {
	cert, key, _ := testCert(t, "c")
	env, m, _ := loginTestEnv(t, &fakeCard{cert: cert, key: key, retries: 3}, []string{"1"})
	m.SetOutput("pgrep -x yubikey-agent", []byte("99\n"))
	env.openCard = func(string) (piv.Card, error) {
		return nil, fmt.Errorf("the smart card cannot be accessed because of other connections outstanding")
	}

	var err error
	_, errOut := capture(t, func() { err = runVaultLogin(devCmd(""), env, loginOpts{mount: "cert"}) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "yubikey-agent")
	assert.Contains(t, errOut, "yubikey-agent")
	for _, c := range m.Calls {
		assert.NotContains(t, []string{"kill", "pkill", "killall"}, c.Name)
	}
}

// The commands must run with no GPG configuration at all.
func TestPivAndVaultCommands_SkipGPGConfigValidation(t *testing.T) {
	for _, c := range []*cobra.Command{newPivCmd(), newVaultCmd()} {
		assert.NotNil(t, c.PersistentPreRunE, c.Name())
		assert.NoError(t, c.PersistentPreRunE(c, nil), c.Name())
	}
}

func TestRegisteredOnRoot(t *testing.T) {
	var names []string
	for _, c := range rootCmd.Commands() {
		names = append(names, c.Name())
	}
	assert.Contains(t, names, "piv")
	assert.Contains(t, names, "vault")
}
