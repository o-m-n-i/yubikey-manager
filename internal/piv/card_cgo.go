//go:build cgo

package piv

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"

	gopiv "github.com/go-piv/piv-go/v2/piv"
)

// OpenCard opens the PIV application of the YubiKey with the given serial.
// The private key never leaves the device: the TLS handshake is signed by the
// card through PC/SC.
func OpenCard(serial string) (Card, error) {
	want, err := strconv.ParseUint(serial, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid serial %q", serial)
	}
	cards, err := gopiv.Cards()
	if err != nil {
		return nil, fmt.Errorf("listing smart cards: %w", err)
	}
	var lastErr error
	for _, name := range cards {
		if !strings.Contains(strings.ToLower(name), "yubikey") {
			continue
		}
		yk, err := gopiv.Open(name)
		if err != nil {
			lastErr = fmt.Errorf("opening %s: %w", name, err)
			continue
		}
		got, err := yk.Serial()
		if err == nil && uint64(got) == want {
			return &card{yk: yk}, nil
		}
		_ = yk.Close()
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("YubiKey %s not found among the smart cards", serial)
}

type card struct{ yk *gopiv.YubiKey }

func (c *card) Certificate() (*x509.Certificate, error) {
	return c.yk.Certificate(gopiv.SlotAuthentication)
}

func (c *card) Retries() (int, error) { return c.yk.Retries() }

func (c *card) Signer(pub crypto.PublicKey, pinPrompt func() (string, error)) (crypto.Signer, error) {
	priv, err := c.yk.PrivateKey(gopiv.SlotAuthentication, pub, gopiv.KeyAuth{PINPrompt: pinPrompt})
	if err != nil {
		return nil, err
	}
	s, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("slot 9a key cannot sign")
	}
	return s, nil
}

func (c *card) Close() error { return c.yk.Close() }

// CardSerials lists the serial numbers of the connected YubiKeys by opening
// each smart card briefly. It needs the same exclusive access as OpenCard, so
// run ReleaseCard first.
func CardSerials() ([]string, error) {
	cards, err := gopiv.Cards()
	if err != nil {
		return nil, fmt.Errorf("listing smart cards: %w", err)
	}
	var serials []string
	var lastErr error
	for _, name := range cards {
		if !strings.Contains(strings.ToLower(name), "yubikey") {
			continue
		}
		yk, err := gopiv.Open(name)
		if err != nil {
			lastErr = fmt.Errorf("opening %s: %w", name, err)
			continue
		}
		serial, err := yk.Serial()
		_ = yk.Close()
		if err != nil {
			lastErr = fmt.Errorf("reading the serial of %s: %w", name, err)
			continue
		}
		serials = append(serials, strconv.FormatUint(uint64(serial), 10))
	}
	if len(serials) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return serials, nil
}
