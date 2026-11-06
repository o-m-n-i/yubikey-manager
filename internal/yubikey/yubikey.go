package yubikey

import (
	"context"
	"fmt"
	"strings"

	"github.com/bobbydams/yubikey-manager/internal/executor"
	"github.com/bobbydams/yubikey-manager/internal/gpg"
)

// YubiKeyService provides operations for interacting with YubiKeys.
type YubiKeyService interface {
	// IsPresent checks if a YubiKey is currently connected.
	IsPresent(ctx context.Context) (bool, error)

	// GetCardInfo returns information about the connected YubiKey.
	GetCardInfo(ctx context.Context) (*gpg.CardInfo, error)

	// EditCard starts an interactive GPG card edit session.
	EditCard(ctx context.Context) error

	// SupportsOpenPGP checks if the connected YubiKey supports OpenPGP functionality.
	// Returns (true, nil) if OpenPGP is supported,
	// (false, nil) if OpenPGP is not supported (e.g., older YubiKey models),
	// (false, error) if unable to determine.
	SupportsOpenPGP(ctx context.Context) (bool, error)
}

// Service implements YubiKeyService.
type Service struct {
	gpgService gpg.GPGService
	exec       executor.Executor
}

// NewService creates a new YubiKey service.
func NewService(gpgService gpg.GPGService, exec executor.Executor) *Service {
	return &Service{
		gpgService: gpgService,
		exec:       exec,
	}
}

// IsPresent checks if a YubiKey is currently connected.
// Returns (true, nil) if YubiKey is present and initialized,
// (false, nil) if no YubiKey is present,
// (false, error) if YubiKey is present but not initialized for OpenPGP or doesn't support it.
func (s *Service) IsPresent(ctx context.Context) (bool, error) {
	_, err := s.gpgService.CardStatus(ctx)
	if err != nil {
		// Check if the error indicates the card is present but not initialized
		errStr := err.Error()
		if strings.Contains(errStr, "Operation not supported by device") ||
			strings.Contains(errStr, "OpenPGP card not available") {
			// Check if the device supports OpenPGP at all
			supports, supportErr := s.SupportsOpenPGP(ctx)
			if supportErr == nil && !supports {
				// We determined it doesn't support OpenPGP
				return false, fmt.Errorf("YubiKey detected but does not support OpenPGP. This YubiKey model (Security Key series) does not have OpenPGP functionality. Only YubiKey 4, 5, and some NEO models support OpenPGP.")
			}
			// If we can't determine support (supportErr != nil) or it does support it,
			// assume it's just not initialized (most common case)
			return false, fmt.Errorf("YubiKey detected but not initialized for OpenPGP. Please initialize it first using 'gpg --card-edit' or 'ykman openpgp reset'")
		}
		// If card status fails with other error, assume no YubiKey is present
		return false, nil
	}
	return true, nil
}

// GetCardInfo returns information about the connected YubiKey.
func (s *Service) GetCardInfo(ctx context.Context) (*gpg.CardInfo, error) {
	info, err := s.gpgService.CardStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get card info: %w", err)
	}
	return info, nil
}

// EditCard starts an interactive GPG card edit session.
func (s *Service) EditCard(ctx context.Context) error {
	args := []string{"--card-edit"}
	return s.exec.RunInteractive(ctx, "gpg", args...)
}

// SupportsOpenPGP checks if the connected YubiKey supports OpenPGP functionality.
// It attempts to detect the YubiKey and check if OpenPGP applet is available.
func (s *Service) SupportsOpenPGP(ctx context.Context) (bool, error) {
	// First, try to check if ykman is available and can detect OpenPGP
	// This is the most reliable method
	ykmanOutput, err := s.exec.Run(ctx, "ykman", "info")
	if err == nil {
		// ykman is available, check if OpenPGP is enabled/available
		outputStr := string(ykmanOutput)
		// Look for "OpenPGP" line and check if it's "Enabled" or "Available"
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OpenPGP") {
				// Check if it says "Not available" or "Disabled"
				if strings.Contains(line, "Not available") || strings.Contains(line, "Disabled") {
					return false, nil
				}
				// If it contains "Enabled" or "Available", it's supported
				if strings.Contains(line, "Enabled") || strings.Contains(line, "Available") {
					return true, nil
				}
			}
		}
		// If ykman output doesn't mention OpenPGP at all, fall through to GPG check
	}

	// Fallback: Try GPG card status
	// If we get "Operation not supported by device", it could mean:
	// 1. Device doesn't support OpenPGP at all
	// 2. OpenPGP applet is not initialized
	// We'll try to distinguish by checking if we can detect the device at all
	_, err = s.gpgService.CardStatus(ctx)
	if err == nil {
		// Successfully got card status, so OpenPGP is supported
		return true, nil
	}

	// Check the error to see if it's a "not supported" vs "not initialized" case
	errStr := err.Error()

	// If the error specifically mentions the device doesn't support the operation,
	// and we can't detect it via ykman either, it likely doesn't support OpenPGP
	if strings.Contains(errStr, "Operation not supported by device") {
		// If ykman was available but showed "Not available", we know it doesn't support it
		// Otherwise, we can't definitively say
		return false, fmt.Errorf("unable to determine if YubiKey supports OpenPGP. The device may not support OpenPGP (some YubiKey models like Security Key don't), or the OpenPGP applet may not be initialized. Try: gpg --card-status or install ykman and run: ykman info")
	}

	// Other errors might indicate the device isn't present or other issues
	return false, fmt.Errorf("unable to check OpenPGP support: %w", err)
}
