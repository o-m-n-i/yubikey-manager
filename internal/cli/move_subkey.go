package cli

import (
	"fmt"
	"strings"

	"github.com/bobbydams/yubikey-manager/internal/executor"
	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
)

func newMoveSubkeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "move-subkey",
		Short: "Move an existing signing subkey to a YubiKey",
		Long: `Move an existing signing subkey to a YubiKey. This command is useful when
you've already created a subkey and need to move it to a YubiKey, or when
resuming a setup process that was interrupted.

This command will:
1. Check for YubiKey presence
2. Guide you through moving the subkey to the YubiKey
3. Optionally remove the master key from your local machine
4. Optionally upload the updated public key to a keyserver`,
		RunE: runMoveSubkey,
	}
}

func runMoveSubkey(cmd *cobra.Command, args []string) error {
	gpgSvc, yubikeySvc, _ := getServices()
	ctx := cmd.Context()

	ui.PrintHeader("Move Subkey to YubiKey")

	// Check YubiKey presence
	present, err := yubikeySvc.IsPresent(ctx)
	if err != nil {
		// Error indicates YubiKey is present but has an issue
		ui.LogError("%v", err)
		fmt.Println()

		// Check if it's a "not supported" vs "not initialized" issue
		errStr := err.Error()
		if strings.Contains(errStr, "does not support OpenPGP") {
			ui.LogWarning("This YubiKey model may not support OpenPGP functionality.")
			fmt.Println()
			ui.LogInfo("To check your YubiKey capabilities:")
			fmt.Println("  - Install ykman: brew install ykman (macOS) or see https://github.com/Yubico/yubikey-manager")
			fmt.Println("  - Run: ykman info")
			fmt.Println()
			return err
		}

		// Otherwise, assume it needs initialization
		ui.LogInfo("To initialize a blank YubiKey for OpenPGP:")
		fmt.Println("  1. Run: gpg --card-edit")
		fmt.Println("  2. Type: admin")
		fmt.Println("  3. Type: factory-reset (WARNING: This will erase all data!)")
		fmt.Println("  4. Type: yes to confirm")
		fmt.Println("  5. Type: quit")
		fmt.Println()
		ui.LogInfo("Alternatively, if you have ykman installed:")
		fmt.Println("  ykman openpgp reset")
		fmt.Println()
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

	// Check PIN retry counter and warn if low or locked
	// This is parsed from gpg --card-status output
	// We'll check via ykman if available, or provide general guidance
	fmt.Println()
	ui.LogInfo("PIN Information:")
	fmt.Println("  • Default User PIN: 123456")
	fmt.Println("  • Default Admin PIN: 12345678")
	fmt.Println("  • If you set PINs in YubiKey Manager app, use those instead")
	fmt.Println("  • Note: YubiKey Authenticator app manages DIFFERENT PINs than OpenPGP!")
	fmt.Println("  • OpenPGP PINs are set via 'gpg --card-edit' → 'admin' → 'passwd'")
	fmt.Println()

	// Check the card's key attributes (what key types it accepts)
	if len(cardInfo.KeyAttributes) > 0 {
		sigAttr := cardInfo.KeyAttributes[0] // First attribute is for signature key
		fmt.Printf("  └─ Signature slot configured for: %s\n", sigAttr)

		// Check if the card is configured for RSA but we're trying to use ECC
		isRSA := strings.HasPrefix(strings.ToLower(sigAttr), "rsa")
		if isRSA {
			ui.LogWarning("Your YubiKey is configured for RSA keys, but your signing subkey may be ECC (ed25519/cv25519).")
			ui.LogWarning("You need to change the card's key attributes before moving an ECC key.")
			fmt.Println()
			ui.LogInfo("To configure the card for ed25519 (required for ECC keys):")
			fmt.Println("  1. Run: gpg --card-edit")
			fmt.Println("  2. Type: admin")
			fmt.Println("  3. Type: key-attr")
			fmt.Println("  4. For Signature key, select: (1) RSA or (2) ECC")
			fmt.Println("     → Select (2) ECC")
			fmt.Println("  5. For curve, select: (1) Curve 25519")
			fmt.Println("  6. Enter Admin PIN when prompted (default: 12345678)")
			fmt.Println("  7. Repeat for Encryption and Authentication if needed")
			fmt.Println("  8. Type: quit")
			fmt.Println()
			if !ui.Confirm("Continue anyway? (keytocard will fail if key types don't match)") {
				return nil
			}
		}
	}

	// Check if YubiKey already has a signing key
	if sigKey, ok := cardInfo.Keys["Signature"]; ok && sigKey != "" && sigKey != "[none]" {
		ui.LogWarning("This YubiKey already has a signature key configured: %s", sigKey)
		if !ui.Confirm("Continue anyway? This will replace the existing signature key.") {
			return nil
		}
	}

	// Verify master key is available (needed for moving subkey)
	keys, err := gpgSvc.ListSecretKeys(ctx, cfg.PrimaryKeyID)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	hasMaster := false
	for _, key := range keys {
		if key.Type == "sec" && key.KeyID == cfg.PrimaryKeyID {
			hasMaster = true
			break
		}
	}

	if !hasMaster {
		ui.LogWarning("Master key not found in keyring. You may need to import it first.")
		fmt.Println()
		fmt.Println("If you have the master key backup, you can import it with:")
		fmt.Println("  gpg --import <path-to-master-key-backup>")
		fmt.Println()
		if !ui.Confirm("Continue anyway? (The subkey move may fail if master key is not available)") {
			return nil
		}
	}

	// Move subkey to YubiKey
	fmt.Println()
	ui.LogWarning("IMPORTANT: 'keytocard' MOVES the key, it doesn't copy it!")
	ui.LogWarning("After moving, the local copy is deleted. If you factory reset")
	ui.LogWarning("the YubiKey without a backup, the key will be PERMANENTLY LOST.")
	fmt.Println()
	ui.LogInfo("Recommended: Create a backup BEFORE moving the key:")
	fmt.Println("  gpg --export-secret-keys", cfg.PrimaryKeyID, "> master-key-backup-$(date +%Y%m%d).gpg")
	fmt.Println()
	if !ui.Confirm("Have you backed up your keys and are ready to proceed?") {
		return nil
	}
	fmt.Println()
	ui.LogInfo("Now we'll move the subkey to your YubiKey.")
	fmt.Println()
	fmt.Println("Steps to move the subkey to YubiKey:")
	fmt.Println()
	fmt.Println("1. Run: gpg --edit-key", cfg.PrimaryKeyID)
	fmt.Println("2. Type: list (to see all subkeys with numbers)")
	fmt.Println("3. Identify the signing subkey you want to move (the one without a card-no)")
	fmt.Println("4. Type: key N (where N is the number of the subkey, e.g., 'key 4')")
	fmt.Println("5. Type: keytocard")
	fmt.Println("6. Select: (1) Signature key")
	fmt.Println("7. Enter your GPG key PASSPHRASE when prompted (this decrypts your key)")
	fmt.Println("8. Enter your YubiKey ADMIN PIN when prompted (default: 12345678)")
	fmt.Println("9. Type: save")
	fmt.Println()
	ui.LogWarning("IMPORTANT: GPG won't show an error if the Admin PIN is wrong!")
	ui.LogWarning("If 'save' says 'Key not changed', the Admin PIN was likely incorrect.")
	fmt.Println()

	_, err = ui.Prompt("Press Enter when ready to continue: ")
	if err != nil {
		return err
	}

	if err := gpgSvc.EditKey(ctx, cfg.PrimaryKeyID); err != nil {
		return fmt.Errorf("failed to edit key: %w", err)
	}

	// Verify the key was actually moved to the YubiKey
	fmt.Println()
	ui.LogInfo("Verifying the key was moved to the YubiKey...")
	cardInfoAfter, err := yubikeySvc.GetCardInfo(ctx)
	if err == nil {
		if sigKey, ok := cardInfoAfter.Keys["Signature"]; ok && sigKey != "" && sigKey != "[none]" {
			ui.LogSuccess("Key successfully moved to YubiKey! Signature key: %s", sigKey)
		} else {
			ui.LogWarning("Key may not have been moved successfully. Signature key slot is still empty.")
			ui.LogWarning("This can happen if:")
			ui.LogWarning("  1. The Admin PIN was incorrect (GPG doesn't show an error for this!)")
			ui.LogWarning("  2. The card's key attributes don't match your key type (RSA vs ECC)")
			ui.LogWarning("  3. The keytocard operation was cancelled")
			fmt.Println()
			ui.LogInfo("To fix Admin PIN issues:")
			fmt.Println("  1. Default Admin PIN is: 12345678")
			fmt.Println("  2. YubiKey Authenticator app uses DIFFERENT PINs than OpenPGP!")
			fmt.Println("  3. To change OpenPGP PINs: gpg --card-edit → admin → passwd")
			fmt.Println()
			ui.LogInfo("To retry:")
			fmt.Println("  1. Run 'gpg --card-status' to check PIN retry counter")
			fmt.Println("  2. If PIN retries are 0, reset PIN via: gpg --card-edit → admin → passwd")
			fmt.Println("  3. Try the move-subkey command again with the correct Admin PIN")
			fmt.Println()
		}
	}

	// Clean up master key
	fmt.Println()
	if ui.Confirm("Remove master key from local machine?") {
		if err := removeMasterKey(ctx, gpgSvc, cfg.PrimaryKeyFingerprint); err != nil {
			ui.LogWarning("Failed to remove master key: %v", err)
		} else {
			ui.LogSuccess("Master key removed from local keyring")
		}
	} else {
		ui.LogWarning("Master key left on machine. Remember to remove it manually!")
	}

	// Upload to keyserver
	if ui.Confirm(fmt.Sprintf("Upload updated public key to %s?", cfg.Keyserver)) {
		exec := executor.NewRealExecutor()
		ui.LogInfo("Uploading to keyserver...")
		_, err := exec.Run(ctx, "gpg", "--keyserver", cfg.Keyserver, "--send-keys", cfg.PrimaryKeyID)
		if err != nil {
			ui.LogWarning("Failed to upload to keyserver: %v", err)
			ui.LogWarning("Visit https://keys.openpgp.org/upload to upload manually.")
		} else {
			ui.LogSuccess("Public key uploaded to %s", cfg.Keyserver)
		}
	}

	fmt.Println()
	ui.LogSuccess("Subkey move complete!")
	ui.LogInfo("Serial: %s", cardInfo.Serial)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Label this YubiKey physically (e.g., 'Key B - " + cardInfo.Serial + "')")
	fmt.Println("  2. Test signing: echo 'test' | gpg --sign --armor")
	fmt.Println("  3. Register this YubiKey with GitHub/GitLab if not already done")
	fmt.Println()

	return nil
}
