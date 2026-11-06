package piv

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/bobbydams/yubikey-manager/internal/executor"
)

// Card is an open PIV application on one YubiKey. Opening it takes the
// smart card exclusively, so gpg's scdaemon (or yubikey-agent) must have let
// go first (see ReleaseCard).
type Card interface {
	// Certificate returns the certificate stored in slot 9a.
	Certificate() (*x509.Certificate, error)
	// Retries returns the PIV PIN attempts left.
	Retries() (int, error)
	// Signer returns a key whose signatures are made on the YubiKey. The PIN
	// is requested through pinPrompt only when the card needs it.
	Signer(pub crypto.PublicKey, pinPrompt func() (string, error)) (crypto.Signer, error)
	Close() error
}

// CardOpener opens the PIV application of the YubiKey with the given serial.
type CardOpener func(serial string) (Card, error)

// yubikeyAgentProcess is the SSH agent that can hold the card the same way
// scdaemon does.
const yubikeyAgentProcess = "yubikey-agent"

// ReleaseCard makes the smart card available for exclusive use. It stops
// gpg's scdaemon (gpg-agent restarts it on demand) and reports, without
// killing it, whether yubikey-agent is running and may still hold the card.
func ReleaseCard(ctx context.Context, exec executor.Executor) (yubikeyAgentRunning bool) {
	_, _ = exec.Run(ctx, "gpgconf", "--kill", "scdaemon")
	out, err := exec.Run(ctx, "pgrep", "-x", yubikeyAgentProcess)
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// ExclusiveAccessHint explains an "other connections outstanding" failure.
func ExclusiveAccessHint(err error, yubikeyAgentRunning bool) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if !strings.Contains(msg, "other connections outstanding") && !strings.Contains(msg, "sharing violation") {
		return err
	}
	if yubikeyAgentRunning {
		return fmt.Errorf("%w\nyubikey-agent is running and probably holds the card; stop it (launchctl or brew services) and retry. ykgpg does not kill it for you", err)
	}
	return fmt.Errorf("%w\nanother program holds the card; stop gpg's scdaemon (gpgconf --kill scdaemon) or close whatever uses the YubiKey", err)
}
