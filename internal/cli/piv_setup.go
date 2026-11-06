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
	certOnly := false // an interrupted run left a key with no certificate
	keyNoCert := occupied && slot.KeyType != "" && !slot.HasCert
	switch {
	case keyNoCert && !force && env.confirm(fmt.Sprintf(
		"Slot 9a on %s holds a key but no certificate, which is what an interrupted setup leaves behind.\nCreate the certificate %s for that key (nothing is destroyed)?", serial, subject)):
		certOnly = true
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
	if (generate || certOnly) && info.PINRetries >= 0 && info.PINRetries < 2 {
		return fmt.Errorf("only %d %s attempt(s) left; not continuing, a wrong entry would block it. Unblock it first with the %s: ykman piv access unblock-pin", info.PINRetries, namePIVPIN, namePIVPUK)
	}
	needMgmt := info.DefaultManagementKey || !info.ManagementKeyStored
	if !generate && !certOnly && !needPIN && !needPUK && !needMgmt {
		ui.LogSuccess("YubiKey %s is already set up. Next: ykgpg piv register --name %s --device %s", serial, name, serial)
		return nil
	}

	printSecretsOverview()
	printSetupPlan(serial, subject, generate, certOnly, needPIN, needPUK, needMgmt)
	if !env.confirm("Continue?") {
		return fmt.Errorf("aborted")
	}

	if generate || certOnly {
		dir, err := env.mkTempDir()
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }() // holds only the public key
		pub := filepath.Join(dir, "slot9a-public.pem")

		if generate {
			printPromptGuide("Step 1: generate the key in slot 9a", mgmtAnswer)
			if err := env.ykman.GenerateKey(ctx, serial, pub); err != nil {
				return fmt.Errorf("generating the slot 9a key: %w\n(nothing else was changed; once the key exists, re-run with --name %s to carry on)", err, name)
			}
		} else if err := env.ykman.ExportPublicKey(ctx, serial, pub); err != nil {
			return err
		}
		printPromptGuide("Step 2: create the certificate "+subject, mgmtAnswer, pivPINAnswer(info.DefaultPIN), "touch the YubiKey when it blinks")
		if err := env.ykman.GenerateCertificate(ctx, serial, subject, certValidDays, pub); err != nil {
			return fmt.Errorf("creating the certificate: %w\n(re-run with --name %s to carry on)", err, name)
		}
	}

	if needPIN {
		printPromptGuide("Step 3: choose a new "+namePIVPIN,
			`"Enter the current PIN" -> the current `+namePIVPIN+` (factory default: 123456)`,
			`"Enter the new PIN" and "Repeat for confirmation" -> your new `+namePIVPIN+`, 6-8 characters`)
		if err := env.ykman.ChangePIN(ctx, serial); err != nil {
			return fmt.Errorf("changing the %s: %w\n(re-run with --name %s to carry on)", namePIVPIN, err, name)
		}
	}
	if needPUK {
		printPromptGuide("Step 3b: choose a new "+namePIVPUK+" (it unblocks the "+namePIVPIN+"; it is not the PIN)",
			`"Enter the current PUK" -> the current `+namePIVPUK+` (factory default: 12345678)`,
			`"Enter the new PUK" and "Repeat for confirmation" -> your new `+namePIVPUK+`, 6-8 characters`)
		if err := env.ykman.ChangePUK(ctx, serial); err != nil {
			return fmt.Errorf("changing the %s: %w\n(re-run with --name %s to carry on)", namePIVPUK, err, name)
		}
	}
	if needMgmt {
		printPromptGuide("Step 4: random "+namePIVMgmt+", stored on the key and unlocked by the "+namePIVPIN,
			`"Enter the current management key [blank to use default key]" -> just press Enter (leave it empty)`,
			`"Enter PIN" -> your `+namePIVPIN+` (the new one if you just changed it)`)
		if err := env.ykman.ProtectManagementKey(ctx, serial); err != nil {
			return fmt.Errorf("setting the %s: %w\n(re-run with --name %s to carry on)", namePIVMgmt, err, name)
		}
	}

	ui.LogSuccess("YubiKey %s is set up. Store the new %s and %s in your password manager, labelled as PIV (not GPG).", serial, namePIVPIN, namePIVPUK)
	ui.LogInfo("Next: ykgpg piv register --name %s --device %s", name, serial)
	return nil
}

func printSetupPlan(serial, subject string, generate, certOnly, pin, puk, mgmt bool) {
	ui.PrintSection("SETUP PLAN FOR YUBIKEY " + serial)
	if generate {
		fmt.Printf("  - generate ECCP256 key in slot 9a (PIN once, touch always)\n")
	}
	if generate || certOnly {
		fmt.Printf("  - self-signed certificate %s, %d days\n", subject, certValidDays)
	}
	if pin {
		fmt.Println("  - replace the factory " + namePIVPIN)
	}
	if puk {
		fmt.Println("  - replace the factory " + namePIVPUK)
	}
	if mgmt {
		fmt.Println("  - random " + namePIVMgmt + ", stored on the key and unlocked by the " + namePIVPIN)
	}
	fmt.Println("ykman asks for these itself; ykgpg never sees them. Before each step ykgpg tells you which prompt wants which secret.")
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
