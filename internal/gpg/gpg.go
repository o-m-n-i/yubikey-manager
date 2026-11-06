package gpg

import (
	"context"
	"fmt"
	"os"

	"github.com/bobbydams/yubikey-manager/internal/executor"
)

// GPGService provides operations for interacting with GPG.
type GPGService interface {
	// ListSecretKeys lists secret keys matching the given key ID.
	ListSecretKeys(ctx context.Context, keyID string) ([]Key, error)

	// CardStatus returns information about the currently connected YubiKey.
	CardStatus(ctx context.Context) (*CardInfo, error)

	// ExportPublicKey exports the public key in armored format.
	ExportPublicKey(ctx context.Context, keyID string) ([]byte, error)

	// ExportSecretSubkeys exports secret subkeys (not the master key).
	ExportSecretSubkeys(ctx context.Context, keyID string) ([]byte, error)

	// DeleteSecretKey deletes a secret key from the keyring.
	DeleteSecretKey(ctx context.Context, fingerprint string) error

	// ImportKey imports a key from the given data.
	ImportKey(ctx context.Context, keyData []byte) error

	// ExportOwnerTrust exports the ownertrust database.
	ExportOwnerTrust(ctx context.Context) ([]byte, error)

	// CheckTrustDB checks and updates the trust database.
	CheckTrustDB(ctx context.Context) error

	// EditKey starts an interactive GPG edit session.
	EditKey(ctx context.Context, keyID string) error
}

// Key represents a GPG key (primary or subkey).
type Key struct {
	Type         string // "sec", "ssb", etc.
	KeyID        string
	Fingerprint  string
	Capabilities []string // [S], [E], [A], etc.
	Expires      string
	CardNo       string // If key is on a card
}

// CardInfo contains information about a YubiKey card.
type CardInfo struct {
	Serial        string
	Cardholder    string
	Keys          map[string]string // "Signature", "Encryption", "Authentication" -> key ID
	KeyAttributes []string          // Key types for each slot, e.g., ["rsa2048", "rsa2048", "rsa2048"]
}

// Service implements GPGService using an executor.
type Service struct {
	exec executor.Executor
}

// NewService creates a new GPG service.
func NewService(exec executor.Executor) *Service {
	return &Service{exec: exec}
}

// ListSecretKeys lists secret keys matching the given key ID.
func (s *Service) ListSecretKeys(ctx context.Context, keyID string) ([]Key, error) {
	args := []string{"--list-secret-keys", "--keyid-format=long", keyID}
	output, err := s.exec.Run(ctx, "gpg", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret keys: %w", err)
	}

	return parseKeyList(output), nil
}

// CardStatus returns information about the currently connected YubiKey.
func (s *Service) CardStatus(ctx context.Context) (*CardInfo, error) {
	args := []string{"--card-status"}
	output, err := s.exec.Run(ctx, "gpg", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get card status: %w", err)
	}

	return parseCardStatus(output), nil
}

// ExportPublicKey exports the public key in armored format.
func (s *Service) ExportPublicKey(ctx context.Context, keyID string) ([]byte, error) {
	args := []string{"--export", "--armor", keyID}
	output, err := s.exec.Run(ctx, "gpg", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to export public key: %w", err)
	}

	return output, nil
}

// ExportSecretSubkeys exports secret subkeys (not the master key).
func (s *Service) ExportSecretSubkeys(ctx context.Context, keyID string) ([]byte, error) {
	args := []string{"--export-secret-subkeys", keyID}
	output, err := s.exec.Run(ctx, "gpg", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to export secret subkeys: %w", err)
	}

	return output, nil
}

// DeleteSecretKey deletes a secret key from the keyring.
func (s *Service) DeleteSecretKey(ctx context.Context, fingerprint string) error {
	args := []string{"--batch", "--yes", "--delete-secret-keys", fingerprint}
	_, err := s.exec.Run(ctx, "gpg", args...)
	if err != nil {
		return fmt.Errorf("failed to delete secret key: %w", err)
	}

	return nil
}

// ImportKey imports a key from the given data.
func (s *Service) ImportKey(ctx context.Context, keyData []byte) error {
	// Write key data to a temporary file
	tmpFile, err := os.CreateTemp("", "gpg-import-*.gpg")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(keyData); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write key data: %w", err)
	}
	tmpFile.Close()

	// Import from the temp file
	args := []string{"--import", tmpFile.Name()}
	_, err = s.exec.Run(ctx, "gpg", args...)
	if err != nil {
		return fmt.Errorf("failed to import key: %w", err)
	}

	return nil
}

// ExportOwnerTrust exports the ownertrust database.
func (s *Service) ExportOwnerTrust(ctx context.Context) ([]byte, error) {
	args := []string{"--export-ownertrust"}
	output, err := s.exec.Run(ctx, "gpg", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to export ownertrust: %w", err)
	}

	return output, nil
}

// CheckTrustDB checks and updates the trust database.
func (s *Service) CheckTrustDB(ctx context.Context) error {
	args := []string{"--check-trustdb"}
	_, err := s.exec.Run(ctx, "gpg", args...)
	if err != nil {
		return fmt.Errorf("failed to check trustdb: %w", err)
	}

	return nil
}

// EditKey starts an interactive GPG edit session.
func (s *Service) EditKey(ctx context.Context, keyID string) error {
	args := []string{"--edit-key", keyID}
	return s.exec.RunInteractive(ctx, "gpg", args...)
}
