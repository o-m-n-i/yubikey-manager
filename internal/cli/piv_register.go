package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bobbydams/yubikey-manager/internal/piv"
	"github.com/bobbydams/yubikey-manager/internal/vault"
	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
)

func newPivRegisterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register --name <name>",
		Short: "Register the slot 9a certificate as Vault cert role yubikey-<name>",
		Long: `Write auth/cert/certs/yubikey-<name> in Vault (policy yubikey-admin, token TTL 8h,
max 24h) with the certificate from slot 9a. Needs an admin Vault token
(~/.vault-token or VAULT_TOKEN) and network access to Vault. Only the public certificate is sent.

Refuses when any role already trusts this certificate, or when the role name is
taken, so duplicate roles cannot come back.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			return runPivRegister(cmd, realPivEnv(), name)
		},
	}
	cmd.Flags().String("name", "", "key name; the role is yubikey-<name> (lower case)")
	return cmd
}

func runPivRegister(cmd *cobra.Command, env *pivEnv, name string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateName(name); err != nil {
		return err
	}
	role := vault.RolePrefix + name

	serial, err := env.resolveDevice(ctx, cmd)
	if err != nil {
		return err
	}
	info, err := env.ykman.Info(ctx, serial)
	if err != nil {
		return err
	}
	if s := info.Slot(piv.SlotAuth); s == nil || !s.HasCert {
		return fmt.Errorf("YubiKey %s has no certificate in slot 9a; run: ykgpg piv setup --name %s --device %s", serial, name, serial)
	}
	cert, err := env.ykman.Certificate(ctx, serial, piv.SlotAuth)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("the slot 9a certificate expired on %s", cert.NotAfter.Format(time.DateOnly))
	}
	fp := piv.Fingerprint(cert)

	token, err := env.resolveToken()
	if err != nil {
		return err
	}
	client, err := env.newVault(token)
	if err != nil {
		return err
	}
	roles, err := client.ListCertRoles(ctx)
	if err != nil {
		return err
	}
	if names := vault.RolesWithFingerprint(roles, fp); len(names) > 0 {
		return fmt.Errorf("this certificate (SHA256 %s) is already registered as %s; not creating a duplicate role", piv.FormatFingerprint(fp), strings.Join(names, ", "))
	}
	for _, r := range roles {
		if r.Name == role {
			return fmt.Errorf("role %s already exists with a different certificate; pick another --name (or remove the old role in Vault first)", role)
		}
	}

	if err := client.RegisterCert(ctx, role, cert); err != nil {
		return err
	}

	// Read it back: a write that Vault accepted but that does not match is
	// worth knowing about now, not during an outage.
	after, err := client.ListCertRoles(ctx)
	if err != nil || len(vault.RolesWithFingerprint(after, fp)) == 0 {
		return fmt.Errorf("wrote %s but could not confirm it by fingerprint; check it in Vault", role)
	}
	ui.LogSuccess("Registered %s (%s, policy %s, TTL %s, max %s)", role, cert.Subject, vault.RolePolicy, vault.RoleTTL, vault.RoleMaxTTL)
	ui.LogInfo("Test it: ykgpg vault login --device %s", serial)
	return nil
}
