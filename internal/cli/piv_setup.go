package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bobbydams/yubikey-manager/internal/piv"
	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
)

const (
	certSubjectPrefix = "CN=yubikey-"
	certValidDays     = 3650 // 10 years
)

func newPivSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup --name <name>",
		Short: "Prepare a YubiKey for Vault login: slot 9a key + certificate, PIN, PUK, management key",
		Long: `Take a YubiKey from factory state to ready for 'ykgpg piv register':

  1. generate an ECCP256 key in slot 9a (PIN once, touch always)
  2. create a self-signed certificate CN=yubikey-<name>, valid 10 years
  3. replace the factory PIV PIN and PUK
  4. set a random AES192 management key, stored on the key and protected by the PIN

ykman asks for the PINs itself, on the terminal. ykgpg never takes a PIN, PUK or
management key as a flag and never logs one. These are the PIV PIN and PUK, NOT
the GPG PIN or Admin PIN.

A slot 9a that already holds a key is never touched without --force: on the main
key it carries the macOS smart-card pairing, SSH through yubikey-agent and the
registered Vault certificate. Re-running setup on a key it set up itself (same
--name) skips straight to the steps still outstanding.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			force, _ := cmd.Flags().GetBool("force")
			return runPivSetup(cmd, realPivEnv(), name, force)
		},
	}
	cmd.Flags().String("name", "", "name for this key, e.g. laptop-a (certificate CN=yubikey-<name>, Vault role yubikey-<name>)")
	cmd.Flags().Bool("force", false, "replace an existing key in slot 9a (destroys it permanently)")
	return cmd
}

func runPivSetup(cmd *cobra.Command, env *pivEnv, name string, force bool) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateName(name); err != nil {
		return err
	}
	serial, err := env.resolveDevice(ctx, cmd)
	if err != nil {
		return err
	}
	info, err := env.ykman.Info(ctx, serial)
	if err != nil {
		return err
	}

	subject := certSubjectPrefix + name
	slot := info.Slot(piv.SlotAuth)
	occupied := slot != nil && (slot.KeyType != "" || slot.HasCert)
	ours := occupied && slot.Subject == subject && slot.KeyType != ""

	generate := !occupied
	switch {
	case occupied && ours:
		ui.LogInfo("Slot 9a already holds the key and certificate %s; skipping key generation.", subject)
	case occupied && !force:
		return fmt.Errorf("%s", refuseOccupiedMessage(serial, slot))
	case occupied && force:
		ui.LogWarning("%s", forceWarning(serial, slot))
		answer, err := env.prompt(fmt.Sprintf("Type the serial number %s to destroy the key in slot 9a: ", serial))
		if err != nil || strings.TrimSpace(answer) != serial {
			return fmt.Errorf("aborted: slot 9a was not touched")
		}
		generate = true
	}

	needPIN, needPUK := info.DefaultPIN, info.DefaultPUK
	needMgmt := info.DefaultManagementKey || !info.ManagementKeyStored
	if !generate && !needPIN && !needPUK && !needMgmt {
		ui.LogSuccess("YubiKey %s is already set up. Next: ykgpg piv register --name %s --device %s", serial, name, serial)
		return nil
	}

	printSetupPlan(serial, subject, generate, needPIN, needPUK, needMgmt)
	if !env.confirm("Continue?") {
		return fmt.Errorf("aborted")
	}

	if generate {
		dir, err := env.mkTempDir()
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir) // holds only the public key
		pub := filepath.Join(dir, "slot9a-public.pem")

		ui.LogInfo("Step 1/4: generating the key in slot 9a. ykman asks for the management key; on a factory key press Enter (blank = default).")
		if err := env.ykman.GenerateKey(ctx, serial, pub); err != nil {
			return fmt.Errorf("generating the slot 9a key: %w\n(nothing else was changed; once the key exists, re-run with --name %s to carry on)", err, name)
		}
		ui.LogInfo("Step 2/4: creating the certificate %s. Enter the PIV PIN (factory default 123456) and touch the key when it blinks.", subject)
		if err := env.ykman.GenerateCertificate(ctx, serial, subject, certValidDays, pub); err != nil {
			return fmt.Errorf("creating the certificate: %w\n(the key exists in slot 9a; re-run with --name %s to carry on)", err, name)
		}
	}

	if needPIN {
		ui.LogInfo("Step 3/4: replace the PIV PIN (6-8 characters; NOT the GPG PIN) and the PUK.")
		if err := env.ykman.ChangePIN(ctx, serial); err != nil {
			return fmt.Errorf("changing the PIV PIN: %w\n(re-run with --name %s to carry on)", err, name)
		}
	}
	if needPUK {
		if err := env.ykman.ChangePUK(ctx, serial); err != nil {
			return fmt.Errorf("changing the PIV PUK: %w\n(re-run with --name %s to carry on)", err, name)
		}
	}
	if needMgmt {
		ui.LogInfo("Step 4/4: random management key, stored on the key, protected by the PIV PIN. Press Enter at the current-key prompt on a factory key.")
		if err := env.ykman.ProtectManagementKey(ctx, serial); err != nil {
			return fmt.Errorf("setting the management key: %w\n(re-run with --name %s to carry on)", err, name)
		}
	}

	ui.LogSuccess("YubiKey %s is set up. Store the new PIV PIN and PUK in your password manager.", serial)
	ui.LogInfo("Next: ykgpg piv register --name %s --device %s", name, serial)
	return nil
}

func printSetupPlan(serial, subject string, generate, pin, puk, mgmt bool) {
	ui.PrintSection("SETUP PLAN FOR YUBIKEY " + serial)
	if generate {
		fmt.Printf("  - generate ECCP256 key in slot 9a (PIN once, touch always)\n  - self-signed certificate %s, %d days\n", subject, certValidDays)
	}
	if pin {
		fmt.Println("  - replace the factory PIV PIN")
	}
	if puk {
		fmt.Println("  - replace the factory PIV PUK")
	}
	if mgmt {
		fmt.Println("  - random AES192 management key, protected by the PIN")
	}
	fmt.Println("The PIV PIN and PUK are separate from the GPG PIN and Admin PIN. ykman will prompt for them; ykgpg never sees them.")
}

func refuseOccupiedMessage(serial string, s *piv.SlotInfo) string {
	return fmt.Sprintf(`slot 9a on YubiKey %s already holds a key (%s)%s.
Generating a new key there would destroy it permanently. Depending on the key, that breaks:
  - macOS smart-card pairing (the login/unlock certificate)
  - SSH through yubikey-agent
  - the Vault certificate login (the registered role stops matching)
Check 'ykgpg piv status' first. If the slot is really disposable, re-run with --force.`,
		serial, orNone(s.KeyType), subjectSuffix(s))
}

func forceWarning(serial string, s *piv.SlotInfo) string {
	return fmt.Sprintf("--force: the existing key in slot 9a of YubiKey %s (%s)%s will be destroyed and cannot be recovered. macOS pairing, yubikey-agent SSH and a registered Vault role that use it stop working.",
		serial, orNone(s.KeyType), subjectSuffix(s))
}

func subjectSuffix(s *piv.SlotInfo) string {
	if s.Subject == "" {
		return ", no certificate"
	}
	return ", certificate " + s.Subject
}

func orNone(s string) string {
	if s == "" {
		return "no private key"
	}
	return s
}
