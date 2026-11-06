package piv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Captured from ykman 5.9.2 on a configured key.
const infoConfigured = `PIV version:              5.7.1
PIN tries remaining:      3/3
PUK tries remaining:      3/3
Management key algorithm: AES192
Management key is stored on the YubiKey, protected by PIN.
CHUID: 00
CCC:   No data available
Slot 9A (AUTHENTICATION):
  Private key type: ECCP256
  Public key type:  ECCP256
  Subject DN:       CN=Example PIV Authentication
  Issuer DN:        CN=Example PIV Authentication
  Serial:           01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14
  Fingerprint:      abcd
  Not before:       2024-01-01T00:00:00+00:00
  Not after:        2054-01-01T00:00:00+00:00

Slot 9C (SIGNATURE):
  Private key type: RSA4096

`

const infoBlank = `PIV version:              5.7.1
PIN tries remaining:      3/3
PUK tries remaining:      3/3
Management key algorithm: TDES
WARNING: Using default PIN!
WARNING: Using default PUK!
WARNING: Using default Management key!
CHUID:                    No data available
CCC:                      No data available
`

func TestParseInfo_Configured(t *testing.T) {
	info, err := ParseInfo(infoConfigured)
	require.NoError(t, err)

	assert.Equal(t, "5.7.1", info.Version)
	assert.Equal(t, 3, info.PINRetries)
	assert.Equal(t, 3, info.PUKRetries)
	assert.False(t, info.DefaultPIN)
	assert.False(t, info.DefaultPUK)
	assert.False(t, info.DefaultManagementKey)
	assert.True(t, info.ManagementKeyStored)
	assert.Equal(t, "AES192", info.ManagementKeyAlgo)

	s := info.Slot("9a")
	require.NotNil(t, s)
	assert.Equal(t, "ECCP256", s.KeyType)
	assert.Equal(t, "CN=Example PIV Authentication", s.Subject)
	assert.True(t, s.HasCert)
	assert.Equal(t, "2054-01-01T00:00:00+00:00", s.NotAfter)

	// A slot with a key but no certificate must still count as occupied.
	c := info.Slot("9C")
	require.NotNil(t, c)
	assert.Equal(t, "RSA4096", c.KeyType)
	assert.False(t, c.HasCert)
}

func TestParseInfo_BlankKey(t *testing.T) {
	info, err := ParseInfo(infoBlank)
	require.NoError(t, err)

	assert.True(t, info.DefaultPIN)
	assert.True(t, info.DefaultPUK)
	assert.True(t, info.DefaultManagementKey)
	assert.False(t, info.ManagementKeyStored)
	assert.Nil(t, info.Slot("9a"))
	assert.Empty(t, info.Slots)
}

func TestParseInfo_Garbage(t *testing.T) {
	_, err := ParseInfo("Error: Failed to connect to YubiKey")
	assert.Error(t, err)
}

func TestParseKeyInfo(t *testing.T) {
	p, err := ParseKeyInfo(`Key slot:               9A (AUTHENTICATION)
Algorithm:              ECCP256
Origin:                 GENERATED
PIN required for use:   ONCE
Touch required for use: ALWAYS
`)
	require.NoError(t, err)
	assert.Equal(t, KeyPolicy{Algorithm: "ECCP256", Origin: "GENERATED", PIN: "ONCE", Touch: "ALWAYS"}, *p)

	_, err = ParseKeyInfo("nope")
	assert.Error(t, err)
}

func TestResolveSerial(t *testing.T) {
	tests := []struct {
		name      string
		connected []string
		wanted    string
		want      string
		errPart   string
	}{
		{"single, no flag", []string{"111111"}, "", "111111", ""},
		{"none connected", nil, "", "", "no YubiKey found"},
		{"several, no flag", []string{"111111", "222222"}, "", "", "--device"},
		{"several, flag", []string{"111111", "222222"}, "222222", "222222", ""},
		{"flag not connected", []string{"111111"}, "999999", "", "not connected"},
		{"flag not a number", []string{"111111"}, "abc", "", "serial number"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveSerial(tt.connected, tt.wanted)
			if tt.errPart != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errPart)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckPIN(t *testing.T) {
	for _, bad := range []string{"", "12345", "123456789"} {
		_, err := CheckPIN(bad)
		assert.Error(t, err, bad)
	}
	for _, ok := range []string{"123456", "12345678"} {
		got, err := CheckPIN(ok)
		assert.NoError(t, err)
		assert.Equal(t, ok, got)
	}
}

func TestParsePinentry(t *testing.T) {
	pin, err := parsePinentry([]byte("OK Pleased\nOK\nOK\nD 12%2034%25\nOK\nOK closing\n"))
	require.NoError(t, err)
	assert.Equal(t, "12 34%", pin)

	_, err = parsePinentry([]byte("OK\nERR 83886179 canceled <Pinentry>\n"))
	assert.Error(t, err)
}

func TestPinentryScript_EscapesPromptAndNamesPIV(t *testing.T) {
	s := pinentryScript("Vault login", "YubiKey PIV PIN (3 left): ")
	assert.Contains(t, s, "SETDESC YubiKey%20PIV%20PIN%20(3%20left):%20\n")
	assert.Contains(t, s, "SETPROMPT PIV%20PIN:")
}
