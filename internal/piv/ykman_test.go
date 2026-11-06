package piv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/bobbydams/yubikey-manager/internal/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func selfSigned(t *testing.T, cn string) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestYkman_Serials(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman list --serials", []byte("11111111\n22222222\n"))

	got, err := NewYkman(m).Serials(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"11111111", "22222222"}, got)
}

func TestYkman_SerialsError(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetError("ykman list --serials", errors.New("exec: ykman: not found"))

	_, err := NewYkman(m).Serials(context.Background())
	assert.ErrorContains(t, err, "brew install ykman")
}

func TestYkman_ReadCommandsAreDeviceScoped(t *testing.T) {
	m := executor.NewMockExecutor()
	m.SetOutput("ykman --device 123456 piv info", []byte(infoBlank))
	y := NewYkman(m)

	info, err := y.Info(context.Background(), "123456")
	require.NoError(t, err)
	assert.True(t, info.DefaultPIN)
	assert.True(t, m.VerifyCall("ykman", "--device", "123456", "piv", "info"))
}

func TestYkman_Certificate(t *testing.T) {
	want, pemText := selfSigned(t, "yubikey-test")
	m := executor.NewMockExecutor()
	m.SetOutput("ykman --device 1 piv certificates export 9a -", []byte(pemText))

	got, err := NewYkman(m).Certificate(context.Background(), "1", "9a")
	require.NoError(t, err)
	assert.Equal(t, Fingerprint(want), Fingerprint(got))
}

// The setup steps that handle secrets must run interactively and must not
// carry a PIN, PUK or management key on the command line.
func TestYkman_SecretStepsAreInteractiveAndFlagFree(t *testing.T) {
	m := executor.NewMockExecutor()
	y := NewYkman(m)
	ctx := context.Background()

	require.NoError(t, y.GenerateKey(ctx, "7", "/tmp/pub.pem"))
	require.NoError(t, y.GenerateCertificate(ctx, "7", "CN=yubikey-x", 3650, "/tmp/pub.pem"))
	require.NoError(t, y.ChangePIN(ctx, "7"))
	require.NoError(t, y.ChangePUK(ctx, "7"))
	require.NoError(t, y.ProtectManagementKey(ctx, "7"))

	assert.Empty(t, m.Calls, "no secret-handling step may use the capturing Run")
	require.Len(t, m.InteractiveCalls, 5)

	forbidden := []string{"-P", "--pin", "-m", "--management-key", "-n", "--new-management-key", "--puk", "--new-pin"}
	for _, c := range m.InteractiveCalls {
		assert.Equal(t, "ykman", c.Name)
		assert.Equal(t, []string{"--device", "7"}, c.Args[:2])
		for _, a := range c.Args {
			assert.NotContains(t, forbidden, a, strings.Join(c.Args, " "))
		}
	}

	assert.Equal(t, []string{"--device", "7", "piv", "keys", "generate", "-a", "ECCP256",
		"--pin-policy", "ONCE", "--touch-policy", "ALWAYS", "9a", "/tmp/pub.pem"}, m.InteractiveCalls[0].Args)
	assert.Equal(t, []string{"--device", "7", "piv", "certificates", "generate", "-s", "CN=yubikey-x",
		"-d", "3650", "9a", "/tmp/pub.pem"}, m.InteractiveCalls[1].Args)
	assert.Equal(t, []string{"--device", "7", "piv", "access", "change-management-key",
		"-a", "AES192", "--generate", "--protect"}, m.InteractiveCalls[4].Args)
}

func TestReleaseCard(t *testing.T) {
	m := executor.NewMockExecutor()
	running := ReleaseCard(context.Background(), m)
	assert.False(t, running)
	assert.True(t, m.VerifyCall("gpgconf", "--kill", "scdaemon"))

	m.SetOutput("pgrep -x yubikey-agent", []byte("4242\n"))
	assert.True(t, ReleaseCard(context.Background(), m))

	m.SetError("pgrep -x yubikey-agent", errors.New("exit status 1"))
	assert.False(t, ReleaseCard(context.Background(), m))
	for _, c := range m.Calls {
		assert.NotEqual(t, "kill", c.Name, "yubikey-agent must never be killed")
		assert.NotEqual(t, "pkill", c.Name)
	}
}

func TestExclusiveAccessHint(t *testing.T) {
	busy := errors.New("the smart card cannot be accessed because of other connections outstanding")
	assert.ErrorContains(t, ExclusiveAccessHint(busy, true), "yubikey-agent")
	assert.ErrorContains(t, ExclusiveAccessHint(busy, false), "scdaemon")
	other := errors.New("boom")
	assert.Equal(t, other, ExclusiveAccessHint(other, true))
	assert.NoError(t, ExclusiveAccessHint(nil, true))
}

func TestFormatFingerprint(t *testing.T) {
	assert.Equal(t, "AB:CD:EF", FormatFingerprint("abcdef"))
}
