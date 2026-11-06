package cli

import (
	"context"
	"fmt"

	"github.com/bobbydams/yubikey-manager/internal/executor"
	"github.com/bobbydams/yubikey-manager/internal/piv"
	"github.com/bobbydams/yubikey-manager/internal/vault"
	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
)

func newVaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "vault",
		Short:             "Vault break-glass login with a YubiKey",
		PersistentPreRunE: skipGPGConfig,
	}
	cmd.PersistentFlags().String("device", "", "serial number of the YubiKey to use (required when several are connected)")
	cmd.AddCommand(newVaultLoginCmd())
	return cmd
}

// loginEnv is what `vault login` needs from the outside world.
type loginEnv struct {
	exec        executor.Executor
	listSerials func() ([]string, error)
	openCard    piv.CardOpener
	newVault    func(addr string) (*vault.Client, error)
	askPIN      func(retries int) (string, error)
	saveToken   func(token string) error
}

func realLoginEnv() *loginEnv {
	return &loginEnv{
		exec:        executor.NewRealExecutor(),
		listSerials: piv.CardSerials,
		openCard:    piv.OpenCard,
		newVault:    func(addr string) (*vault.Client, error) { return vault.NewClient(addr, "") },
		askPIN:      func(retries int) (string, error) { return piv.PromptPIN("Vault", retries) },
		saveToken:   vault.SaveToken,
	}
}

type loginOpts struct {
	addr, mount, role string
	device            string
	printToken        bool
	noSave            bool
}

func newVaultLoginCmd() *cobra.Command {
	var o loginOpts
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to Vault with the certificate in YubiKey slot 9a",
		Long: `Log in to Vault's cert auth method with the PIV key in slot 9a. The TLS
client handshake is signed on the YubiKey, so the private key never leaves it;
the vault CLI and curl cannot do this.

The PIV PIN is read from the terminal, or from a pinentry-mac dialog when there
is no terminal. It is the PIV PIN, NOT your GPG PIN or Admin PIN. ykgpg refuses
to try a PIN when only one attempt is left, so it can never lock the PIV app.

Without --role, Vault picks the role whose certificate matches the key, so this
works for any registered YubiKey. The token is saved to ~/.vault-token (0600);
only the role, policies and TTL are printed. The token itself is printed only
with --print-token.

Opening the card needs exclusive access. ykgpg stops gpg's scdaemon first
(gpg-agent restarts it on demand). If yubikey-agent is running it only tells you.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.device, _ = cmd.Flags().GetString("device")
			return runVaultLogin(cmd, realLoginEnv(), o)
		},
	}
	cmd.Flags().StringVar(&o.addr, "addr", vault.AddrFromEnv(), "Vault address (default $VAULT_ADDR)")
	cmd.Flags().StringVar(&o.mount, "mount", vault.DefaultMount, "cert auth mount path")
	cmd.Flags().StringVar(&o.role, "role", "", "cert auth role; empty lets Vault pick the role matching the YubiKey")
	cmd.Flags().BoolVar(&o.printToken, "print-token", false, "also print an export VAULT_TOKEN=... line on stdout (the token is a secret)")
	cmd.Flags().BoolVar(&o.noSave, "no-save", false, "don't write ~/.vault-token")
	return cmd
}

func runVaultLogin(cmd *cobra.Command, env *loginEnv, o loginOpts) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	agentRunning := piv.ReleaseCard(ctx, env.exec)
	serials, err := env.listSerials()
	if err != nil {
		return piv.ExclusiveAccessHint(err, agentRunning)
	}
	serial, err := piv.ResolveSerial(serials, o.device)
	if err != nil {
		return err
	}
	if agentRunning {
		ui.LogWarning("yubikey-agent is running and may hold the card. If opening it fails, stop it first; ykgpg will not kill it.")
	}

	card, err := env.openCard(serial)
	if err != nil {
		return piv.ExclusiveAccessHint(fmt.Errorf("opening YubiKey %s: %w", serial, err), agentRunning)
	}
	defer card.Close()

	client, err := env.newVault(o.addr)
	if err != nil {
		return err
	}
	res, err := client.LoginWithCard(ctx, card, o.mount, o.role, func(retries int) (string, error) {
		pin, err := env.askPIN(retries)
		if err == nil {
			ui.LogInfo("If the YubiKey blinks, touch it.")
		}
		return pin, err
	})
	if err != nil {
		return piv.ExclusiveAccessHint(err, agentRunning)
	}

	saved := ""
	if !o.noSave {
		if err := env.saveToken(res.Token); err != nil {
			return fmt.Errorf("saving ~/.vault-token: %w", err)
		}
		saved = " (saved to ~/.vault-token)"
	}
	ui.LogSuccess("Logged in to %s as cert role %q: policies %v, TTL %s%s", o.addr, res.CertName, res.Policies, res.TTL, saved)
	if o.printToken {
		fmt.Printf("export VAULT_TOKEN='%s'\n", res.Token)
	}
	return nil
}
