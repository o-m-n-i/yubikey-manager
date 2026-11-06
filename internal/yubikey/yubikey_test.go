package yubikey

import (
	"context"
	"fmt"
	"testing"

	"github.com/bobbydams/yubikey-manager/internal/executor"
	"github.com/bobbydams/yubikey-manager/internal/gpg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockGPGService is a simple mock implementation of GPGService for testing.
type MockGPGService struct {
	CardStatusFunc func(ctx context.Context) (*gpg.CardInfo, error)
}

func (m *MockGPGService) ListSecretKeys(ctx context.Context, keyID string) ([]gpg.Key, error) {
	return nil, nil
}

func (m *MockGPGService) CardStatus(ctx context.Context) (*gpg.CardInfo, error) {
	if m.CardStatusFunc != nil {
		return m.CardStatusFunc(ctx)
	}
	return nil, nil
}

func (m *MockGPGService) ExportPublicKey(ctx context.Context, keyID string) ([]byte, error) {
	return nil, nil
}

func (m *MockGPGService) ExportSecretSubkeys(ctx context.Context, keyID string) ([]byte, error) {
	return nil, nil
}

func (m *MockGPGService) DeleteSecretKey(ctx context.Context, fingerprint string) error {
	return nil
}

func (m *MockGPGService) ImportKey(ctx context.Context, keyData []byte) error {
	return nil
}

func (m *MockGPGService) ExportOwnerTrust(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (m *MockGPGService) CheckTrustDB(ctx context.Context) error {
	return nil
}

func (m *MockGPGService) EditKey(ctx context.Context, keyID string) error {
	return nil
}

func TestService_IsPresent(t *testing.T) {
	tests := []struct {
		name          string
		cardStatusErr error
		expected      bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "yubikey present",
			cardStatusErr: nil,
			expected:      true,
			expectError:   false,
		},
		{
			name:          "yubikey not present",
			cardStatusErr: assert.AnError,
			expected:      false,
			expectError:   false,
		},
		{
			name:          "yubikey present but not initialized",
			cardStatusErr: fmt.Errorf("gpg: selecting card failed: Operation not supported by device"),
			expected:      false,
			expectError:   true,
			errorContains: "not initialized for OpenPGP",
		},
		{
			name:          "yubikey present but OpenPGP card not available",
			cardStatusErr: fmt.Errorf("gpg: OpenPGP card not available: Operation not supported by device"),
			expected:      false,
			expectError:   true,
			errorContains: "not initialized for OpenPGP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGPG := &MockGPGService{
				CardStatusFunc: func(ctx context.Context) (*gpg.CardInfo, error) {
					if tt.cardStatusErr != nil {
						return nil, tt.cardStatusErr
					}
					return &gpg.CardInfo{Serial: "12345678"}, nil
				},
			}
			mockExec := executor.NewMockExecutor()
			svc := NewService(mockGPG, mockExec)

			present, err := svc.IsPresent(context.Background())

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expected, present)
		})
	}
}

func TestService_GetCardInfo(t *testing.T) {
	expectedCardInfo := &gpg.CardInfo{
		Serial:     "12345678",
		Cardholder: "Test User",
		Keys: map[string]string{
			"Signature": "ABC123",
		},
	}

	mockGPG := &MockGPGService{
		CardStatusFunc: func(ctx context.Context) (*gpg.CardInfo, error) {
			return expectedCardInfo, nil
		},
	}
	mockExec := executor.NewMockExecutor()
	svc := NewService(mockGPG, mockExec)

	cardInfo, err := svc.GetCardInfo(context.Background())

	require.NoError(t, err)
	assert.Equal(t, expectedCardInfo, cardInfo)
}

func TestService_SupportsOpenPGP(t *testing.T) {
	tests := []struct {
		name          string
		ykmanOutput   string
		ykmanError    error
		cardStatusErr error
		expected      bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "ykman shows OpenPGP support",
			ykmanOutput: "Device type: YubiKey 5\nApplications:\n  OpenPGP: Enabled",
			ykmanError:  nil,
			expected:    true,
			expectError: false,
		},
		{
			name:        "ykman shows OpenPGP not available",
			ykmanOutput: "Device type: Security Key C NFC\nApplications:\n  OpenPGP: Not available",
			ykmanError:  nil,
			expected:    false,
			expectError: false,
		},
		{
			name:          "ykman not available, GPG card status works",
			ykmanError:    fmt.Errorf("ykman not found"),
			cardStatusErr: nil,
			expected:      true,
			expectError:   false,
		},
		{
			name:          "ykman not available, GPG fails with operation not supported",
			ykmanError:    fmt.Errorf("ykman not found"),
			cardStatusErr: fmt.Errorf("gpg: selecting card failed: Operation not supported by device"),
			expected:      false,
			expectError:   true,
			errorContains: "unable to determine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGPG := &MockGPGService{
				CardStatusFunc: func(ctx context.Context) (*gpg.CardInfo, error) {
					if tt.cardStatusErr != nil {
						return nil, tt.cardStatusErr
					}
					return &gpg.CardInfo{Serial: "12345678"}, nil
				},
			}
			mockExec := executor.NewMockExecutor()

			// Set up ykman mock
			if tt.ykmanError != nil {
				mockExec.SetError("ykman info", tt.ykmanError)
			} else {
				mockExec.SetOutput("ykman info", []byte(tt.ykmanOutput))
			}

			svc := NewService(mockGPG, mockExec)

			supports, err := svc.SupportsOpenPGP(context.Background())

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expected, supports)
		})
	}
}
