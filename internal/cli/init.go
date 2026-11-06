package cli

import (
	"fmt"

	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new YubiKey for OpenPGP use",
		Long: `Initialize a new YubiKey for OpenPGP use. This command guides you through:

1. Checking the current card status
2. Changing the default PINs (recommended for security)
3. Setting key attributes (RSA vs ECC/ed25519)
4. Optionally setting cardholder name

Run this command on a new or factory-reset YubiKey before using it for GPG keys.`,
		RunE: runInit,
	}
	// Skip PersistentPreRunE validation for init command
	// This command should work even without a valid config file
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}
	return cmd
}

func runInit(cmd *cobra.Command, args []string) error {
	_, yubikeySvc, _ := getServices()
	ctx := cmd.Context()

	ui.PrintHeader("Initialize YubiKey for OpenPGP")

	// Check YubiKey presence
	present, err := yubikeySvc.IsPresent(ctx)
	if err != nil {
		ui.LogError("%v", err)
		return err
	}
	if !present {
		ui.LogError("No YubiKey detected. Please insert a YubiKey and try again.")
		return fmt.Errorf("no YubiKey detected")
	}

	cardInfo, err := yubikeySvc.GetCardInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get card info: %w", err)
	}

	ui.LogInfo("Detected YubiKey with serial: %s", cardInfo.Serial)

	// Show current status
	fmt.Println()
	ui.PrintSection("CURRENT CARD STATUS")
	fmt.Printf("  Serial:      %s\n", cardInfo.Serial)
	fmt.Printf("  Cardholder:  %s\n", valueOrDefault(cardInfo.Cardholder, "[not set]"))

	if len(cardInfo.KeyAttributes) > 0 {
		fmt.Printf("  Key types:   %v\n", cardInfo.KeyAttributes)
	}

	// Show existing keys
	hasKeys := false
	if sigKey, ok := cardInfo.Keys["Signature"]; ok && sigKey != "" {
		fmt.Printf("  Signature:   %s\n", sigKey)
		hasKeys = true
	}
	if encKey, ok := cardInfo.Keys["Encryption"]; ok && encKey != "" {
		fmt.Printf("  Encryption:  %s\n", encKey)
		hasKeys = true
	}
	if authKey, ok := cardInfo.Keys["Authentication"]; ok && authKey != "" {
		fmt.Printf("  Auth:        %s\n", authKey)
		hasKeys = true
	}

	if hasKeys {
		fmt.Println()
		ui.LogWarning("This YubiKey already has keys configured.")
		ui.LogWarning("Changing key attributes will NOT affect existing keys on the card.")
		ui.LogWarning("To start fresh, factory reset the card first: gpg --card-edit → admin → factory-reset")
	}

	// PIN Information
	fmt.Println()
	ui.PrintSection("PIN INFORMATION")
	fmt.Println()
	fmt.Println("  YubiKey OpenPGP uses TWO separate PINs:")
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("  │ PIN Type    │ Default  │ Min Length │ Used For                          │")
	fmt.Println("  ├─────────────┼──────────┼────────────┼───────────────────────────────────┤")
	fmt.Println("  │ User PIN    │ 123456   │ 6 chars    │ Signing, decrypting, auth         │")
	fmt.Println("  │ Admin PIN   │ 12345678 │ 8 chars    │ Card management, moving keys      │")
	fmt.Println("  └──────────────────────────────────────────────────────────────────────────┘")
	fmt.Println()
	ui.LogWarning("IMPORTANT: These are NOT the same PINs as YubiKey Authenticator or FIDO2!")
	ui.LogWarning("OpenPGP PINs are managed separately via GPG.")
	fmt.Println()

	// Change PINs
	if ui.Confirm("Change default PINs? (Highly recommended for new cards)") {
		fmt.Println()
		ui.LogInfo("Launching GPG card editor to change PINs...")
		fmt.Println()
		fmt.Println("Steps to change PINs:")
		fmt.Println("  1. Type: admin")
		fmt.Println("  2. Type: passwd")
		fmt.Println("  3. Select (1) to change User PIN")
		fmt.Println("     - Enter CURRENT PIN: 123456 (default)")
		fmt.Println("     - Enter NEW PIN (minimum 6 characters)")
		fmt.Println("     - Confirm NEW PIN")
		fmt.Println("  4. Select (3) to change Admin PIN")
		fmt.Println("     - Enter CURRENT Admin PIN: 12345678 (default)")
		fmt.Println("     - Enter NEW Admin PIN (minimum 8 characters)")
		fmt.Println("     - Confirm NEW Admin PIN")
		fmt.Println("  5. Optionally select (4) to set Reset Code (for PIN recovery)")
		fmt.Println("  6. Press Q to exit passwd menu, then type: quit")
		fmt.Println()
		ui.LogWarning("PIN prompts ask for CURRENT pin first, then NEW pin!")
		fmt.Println()

		_, err = ui.Prompt("Press Enter to continue: ")
		if err != nil {
			return err
		}

		if err := yubikeySvc.EditCard(ctx); err != nil {
			ui.LogWarning("Card edit session ended: %v", err)
		}
	}

	// Key Attributes
	fmt.Println()
	ui.PrintSection("KEY ALGORITHM CONFIGURATION")
	fmt.Println()
	fmt.Println("  Your YubiKey can store RSA or ECC (elliptic curve) keys.")
	fmt.Println("  You must configure the card's key type BEFORE moving keys to it.")
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("  │ Algorithm   │ Security │ Speed    │ Compatibility               │")
	fmt.Println("  ├─────────────┼──────────┼──────────┼─────────────────────────────┤")
	fmt.Println("  │ RSA 2048    │ Good     │ Slow     │ Maximum (older systems)     │")
	fmt.Println("  │ RSA 4096    │ Better   │ Very slow│ Good                        │")
	fmt.Println("  │ ed25519     │ Excellent│ Fast     │ Modern systems (recommended)│")
	fmt.Println("  └──────────────────────────────────────────────────────────────────┘")
	fmt.Println()

	if len(cardInfo.KeyAttributes) > 0 {
		fmt.Printf("  Current configuration: %v\n", cardInfo.KeyAttributes)
		fmt.Println()
	}

	if ui.Confirm("Change key algorithm to ed25519/cv25519? (Recommended for new keys)") {
		fmt.Println()
		ui.LogInfo("Launching GPG card editor to change key attributes...")
		fmt.Println()
		fmt.Println("Steps to configure for ed25519:")
		fmt.Println("  1. Type: admin")
		fmt.Println("  2. Type: key-attr")
		fmt.Println("  3. For Signature key:")
		fmt.Println("     - Select (2) ECC")
		fmt.Println("     - Select (1) Curve 25519")
		fmt.Println("  4. For Encryption key:")
		fmt.Println("     - Select (2) ECC")
		fmt.Println("     - Select (1) Curve 25519")
		fmt.Println("  5. For Authentication key:")
		fmt.Println("     - Select (2) ECC")
		fmt.Println("     - Select (1) Curve 25519")
		fmt.Println("  6. Enter Admin PIN when prompted")
		fmt.Println("  7. Type: quit")
		fmt.Println()
		ui.LogWarning("Note: You'll be prompted for Admin PIN (default: 12345678)")
		fmt.Println()

		_, err = ui.Prompt("Press Enter to continue: ")
		if err != nil {
			return err
		}

		if err := yubikeySvc.EditCard(ctx); err != nil {
			ui.LogWarning("Card edit session ended: %v", err)
		}
	}

	// Cardholder name
	fmt.Println()
	if ui.Confirm("Set cardholder name on the card? (Helps identify which key is which)") {
		fmt.Println()
		ui.LogInfo("Launching GPG card editor to set cardholder info...")
		fmt.Println()
		fmt.Println("Steps to set cardholder name:")
		fmt.Println("  1. Type: admin")
		fmt.Println("  2. Type: name")
		fmt.Println("     - Enter surname (last name)")
		fmt.Println("     - Enter given name (first name)")
		fmt.Println("  3. Type: lang")
		fmt.Println("     - Enter 'en' for English")
		fmt.Println("  4. Type: quit")
		fmt.Println()

		_, err = ui.Prompt("Press Enter to continue: ")
		if err != nil {
			return err
		}

		if err := yubikeySvc.EditCard(ctx); err != nil {
			ui.LogWarning("Card edit session ended: %v", err)
		}
	}

	// Final status
	fmt.Println()
	ui.LogInfo("Checking final card status...")
	cardInfoFinal, err := yubikeySvc.GetCardInfo(ctx)
	if err == nil {
		fmt.Println()
		ui.PrintSection("FINAL CARD STATUS")
		fmt.Printf("  Serial:      %s\n", cardInfoFinal.Serial)
		fmt.Printf("  Cardholder:  %s\n", valueOrDefault(cardInfoFinal.Cardholder, "[not set]"))
		if len(cardInfoFinal.KeyAttributes) > 0 {
			fmt.Printf("  Key types:   %v\n", cardInfoFinal.KeyAttributes)
		}
	}

	fmt.Println()
	ui.LogSuccess("YubiKey initialization complete!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Run 'ykgpg setup' to create a new signing subkey and move it to this YubiKey")
	fmt.Println("  2. Or run 'ykgpg move-subkey' if you already have a subkey to move")
	fmt.Println("  3. Label this YubiKey physically with its serial number: " + cardInfo.Serial)
	fmt.Println()

	return nil
}

// valueOrDefault returns the value if non-empty, otherwise the default.
func valueOrDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}
