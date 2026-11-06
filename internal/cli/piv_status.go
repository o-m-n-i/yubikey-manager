package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/bobbydams/yubikey-manager/internal/piv"
	"github.com/bobbydams/yubikey-manager/internal/vault"
	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
)

func newPivStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show PIV state and Vault registration of the connected YubiKeys",
		Long: `Show, for each connected YubiKey: the serial, whether the PIN, PUK and
management key are still factory defaults, the slot 9a key type and policies,
the certificate subject, and whether that certificate is registered in Vault.

This only reads (ykman piv info does not use up a PIN attempt). Without --device
it lists every connected key. The Vault check needs a token (~/.vault-token or
VAULT_TOKEN) and network access to Vault; without them it says "unknown".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			skipVault, _ := cmd.Flags().GetBool("skip-vault")
			return runPivStatus(cmd, realPivEnv(), skipVault)
		},
	}
	cmd.Flags().Bool("skip-vault", false, "don't check Vault registration")
	return cmd
}

func runPivStatus(cmd *cobra.Command, env *pivEnv, skipVault bool) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	wanted, _ := cmd.Flags().GetString("device")

	serials, err := env.ykman.Serials(ctx)
	if err != nil {
		return err
	}
	if len(serials) == 0 {
		return fmt.Errorf("no YubiKey found; insert it and try again")
	}
	if wanted != "" {
		s, err := piv.ResolveSerial(serials, wanted)
		if err != nil {
			return err
		}
		serials = []string{s}
	}

	var roles []vault.CertRole
	vaultNote := ""
	if skipVault {
		vaultNote = "not checked (--skip-vault)"
	} else if roles, err = env.listVaultRoles(ctx); err != nil {
		vaultNote = "unknown (" + err.Error() + ")"
	}

	ui.PrintHeader("YubiKey PIV Status")
	for _, serial := range serials {
		if err := env.printKeyStatus(ctx, serial, roles, vaultNote); err != nil {
			ui.LogError("YubiKey %s: %v", serial, err)
		}
	}
	return nil
}

func (e *pivEnv) listVaultRoles(ctx context.Context) ([]vault.CertRole, error) {
	token, err := e.resolveToken()
	if err != nil {
		return nil, err
	}
	client, err := e.newVault(token)
	if err != nil {
		return nil, err
	}
	return client.ListCertRoles(ctx)
}

func (e *pivEnv) printKeyStatus(ctx context.Context, serial string, roles []vault.CertRole, vaultNote string) error {
	info, err := e.ykman.Info(ctx, serial)
	if err != nil {
		return err
	}

	_, _ = ui.HeaderColor.Fprintf(e.out, "YUBIKEY %s\n", serial)
	e.kv("PIV version", info.Version)
	e.kv("PIN", credentialState(info.DefaultPIN, info.PINRetries))
	e.kv("PUK", credentialState(info.DefaultPUK, info.PUKRetries))
	switch {
	case info.DefaultManagementKey:
		e.kv("Management key", "factory default (run: ykgpg piv setup)")
	case info.ManagementKeyStored:
		e.kv("Management key", "random, stored on the key, protected by the PIN ("+info.ManagementKeyAlgo+")")
	default:
		e.kv("Management key", "custom, not stored on the key ("+info.ManagementKeyAlgo+")")
	}

	slot := info.Slot(piv.SlotAuth)
	if slot == nil {
		e.kv("Slot 9a", "empty")
		e.kv("Vault", "not registered (no certificate)")
		_, _ = fmt.Fprintln(e.out)
		return nil
	}

	if slot.KeyType == "" {
		e.kv("Slot 9a", "certificate only, no private key")
	} else if pol, err := e.ykman.KeyPolicy(ctx, serial, piv.SlotAuth); err == nil {
		e.kv("Slot 9a", describeTouch(pol))
	} else {
		e.kv("Slot 9a", slot.KeyType+" (policies unreadable: "+err.Error()+")")
	}

	if !slot.HasCert {
		e.kv("Certificate", "none")
		e.kv("Vault", "not registered (no certificate)")
		_, _ = fmt.Fprintln(e.out)
		return nil
	}
	e.kv("Certificate", slot.Subject)
	e.kv("Valid until", slot.NotAfter)

	cert, err := e.ykman.Certificate(ctx, serial, piv.SlotAuth)
	if err != nil {
		e.kv("Vault", "unknown ("+err.Error()+")")
		_, _ = fmt.Fprintln(e.out)
		return nil
	}
	fp := piv.Fingerprint(cert)
	e.kv("Fingerprint", "SHA256 "+piv.FormatFingerprint(fp))

	switch {
	case vaultNote != "":
		e.kv("Vault", vaultNote)
	default:
		if names := vault.RolesWithFingerprint(roles, fp); len(names) > 0 {
			e.kv("Vault", "registered as "+strings.Join(names, ", "))
		} else {
			e.kv("Vault", "NOT registered (run: ykgpg piv register --name <name>)")
		}
	}
	_, _ = fmt.Fprintln(e.out)
	return nil
}

func credentialState(isDefault bool, retries int) string {
	state := "changed"
	if isDefault {
		state = "factory default (run: ykgpg piv setup)"
	}
	if retries >= 0 {
		state += fmt.Sprintf(", %d tries left", retries)
	}
	return state
}
