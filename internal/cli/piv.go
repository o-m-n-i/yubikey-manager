package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/bobbydams/yubikey-manager/internal/executor"
	"github.com/bobbydams/yubikey-manager/internal/piv"
	"github.com/bobbydams/yubikey-manager/internal/vault"
	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
)

// pivEnv holds everything the piv commands touch outside the process, so the
// command logic can run against mocks.
type pivEnv struct {
	exec         executor.Executor
	ykman        *piv.Ykman
	newVault     func(token string) (*vault.Client, error)
	resolveToken func() (string, error)
	confirm      func(prompt string) bool
	prompt       func(prompt string) (string, error)
	mkTempDir    func() (string, error)
	out          io.Writer // status tables
}

func realPivEnv() *pivEnv {
	exec := executor.NewRealExecutor()
	return &pivEnv{
		exec:  exec,
		ykman: piv.NewYkman(exec),
		newVault: func(token string) (*vault.Client, error) {
			return vault.NewClient(vault.AddrFromEnv(), token)
		},
		resolveToken: vault.ResolveToken,
		confirm:      ui.Confirm,
		prompt:       ui.Prompt,
		mkTempDir:    func() (string, error) { return os.MkdirTemp("", "ykgpg-piv-") },
		out:          os.Stdout,
	}
}

// skipGPGConfig replaces the root PersistentPreRunE for commands that have
// nothing to do with the GPG configuration: piv and vault must work on a
// machine with no ~/.config/ykgpg/config.yaml.
func skipGPGConfig(cmd *cobra.Command, args []string) error {
	if noColor, _ := cmd.Flags().GetBool("no-color"); noColor {
		ui.SetColorEnabled(false)
	}
	return nil
}

func newPivCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "piv",
		Short: "Prepare a YubiKey's PIV application (for Vault break-glass login)",
		Long: `Manage the PIV application of a YubiKey: slot 9a holds the key and
certificate used to log in to Vault when your usual login is unavailable.

The PIV application has its own PIN and PUK. They are NOT the OpenPGP PIN or
Admin PIN that GPG uses.`,
		PersistentPreRunE: skipGPGConfig,
	}
	cmd.PersistentFlags().String("device", "", "serial number of the YubiKey to act on (required when several are connected)")
	cmd.AddCommand(newPivStatusCmd(), newPivSetupCmd(), newPivRegisterCmd())
	return cmd
}

// roleNameRE keeps role names lowercase: Vault 2.x matches ACL role names in
// lowercase.
var roleNameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("--name is required (e.g. --name laptop-a)")
	}
	if !roleNameRE.MatchString(name) {
		return fmt.Errorf("invalid --name %q: use lower-case letters, digits and single dashes (Vault 2.x matches role names in lower case)", name)
	}
	return nil
}

// resolveDevice applies the --device rule: with several YubiKeys connected, a
// serial is mandatory.
func (e *pivEnv) resolveDevice(ctx context.Context, cmd *cobra.Command) (string, error) {
	wanted, _ := cmd.Flags().GetString("device")
	serials, err := e.ykman.Serials(ctx)
	if err != nil {
		return "", err
	}
	return piv.ResolveSerial(serials, wanted)
}

func describeTouch(p *piv.KeyPolicy) string {
	return fmt.Sprintf("%s, PIN %s, touch %s", p.Algorithm, strings.ToLower(p.PIN), strings.ToLower(p.Touch))
}

// kv prints one "label: value" line of a status table.
func (e *pivEnv) kv(key, value string) {
	_, _ = ui.LabelColor.Fprintf(e.out, "%-16s ", key+":")
	_, _ = ui.ValueColor.Fprintln(e.out, value)
}
