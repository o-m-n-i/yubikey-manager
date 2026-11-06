package cli

import (
	"fmt"

	"github.com/bobbydams/yubikey-manager/internal/backup"
	"github.com/bobbydams/yubikey-manager/internal/config"
	"github.com/bobbydams/yubikey-manager/internal/executor"
	"github.com/bobbydams/yubikey-manager/internal/gpg"
	"github.com/bobbydams/yubikey-manager/internal/yubikey"
	"github.com/bobbydams/yubikey-manager/pkg/ui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfg     *config.Config
	rootCmd *cobra.Command
	version = "dev"
)

// Execute runs the CLI application.
func Execute() error {
	return rootCmd.Execute()
}

// SetVersion sets the version string (used by build process).
func SetVersion(v string) {
	version = v
	rootCmd.Version = v
}

func init() {
	rootCmd = &cobra.Command{
		Use:          "ykgpg",
		Short:        "YubiKey GPG Manager - Manage GPG signing subkeys across multiple YubiKeys",
		SilenceUsage: true, // Don't print usage on errors
		Long: `YubiKey GPG Manager is a tool for managing GPG signing subkeys across multiple YubiKeys.

It provides commands for:
  - Setting up new YubiKeys with signing subkeys
  - Revoking compromised subkeys
  - Extending key expiration dates
  - Managing key backups
  - Verifying setup
  - Preparing YubiKeys for Vault break-glass login (piv, vault)`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Check for no-color flag first (before loading config)
			noColor, _ := cmd.Flags().GetBool("no-color")
			if noColor {
				ui.SetColorEnabled(false)
			}

			// Load configuration
			var err error
			cfg, err = config.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Bind flags to viper
			bindFlags(cmd)

			// Reload config after binding flags
			cfg, err = config.Load()
			if err != nil {
				return fmt.Errorf("failed to reload config: %w", err)
			}

			// Apply color setting from config (flag takes precedence)
			if !noColor && cfg.NoColor {
				ui.SetColorEnabled(false)
			}

			// Validate required config
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}

			return nil
		},
	}

	// Global flags
	rootCmd.PersistentFlags().String("key-id", "", "Primary key ID (overrides config)")
	rootCmd.PersistentFlags().String("fingerprint", "", "Primary key fingerprint (overrides config)")
	rootCmd.PersistentFlags().String("name", "", "User name (overrides config)")
	rootCmd.PersistentFlags().String("email", "", "User email (overrides config)")
	rootCmd.PersistentFlags().String("keyserver", "", "Keyserver URL (overrides config)")
	rootCmd.PersistentFlags().String("master-key-path", "", "Path to master key backup (overrides config)")
	rootCmd.PersistentFlags().String("backup-dir", "", "Backup directory (overrides config)")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")

	// Add subcommands
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newSetupCmd())
	rootCmd.AddCommand(newSetupBatchCmd())
	rootCmd.AddCommand(newMoveSubkeyCmd())
	rootCmd.AddCommand(newRevokeCmd())
	rootCmd.AddCommand(newExtendCmd())
	rootCmd.AddCommand(newCleanupCmd())
	rootCmd.AddCommand(newMetadataCmd())
	rootCmd.AddCommand(newExportCmd())
	rootCmd.AddCommand(newVerifyCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newPivCmd())
	rootCmd.AddCommand(newVaultCmd())

	// Set version after command is created
	rootCmd.Version = version
}

// bindFlags binds Cobra flags to Viper.
func bindFlags(cmd *cobra.Command) {
	_ = viper.BindPFlag("primary_key_id", cmd.Flags().Lookup("key-id"))
	_ = viper.BindPFlag("primary_key_fingerprint", cmd.Flags().Lookup("fingerprint"))
	_ = viper.BindPFlag("user_name", cmd.Flags().Lookup("name"))
	_ = viper.BindPFlag("user_email", cmd.Flags().Lookup("email"))
	_ = viper.BindPFlag("keyserver", cmd.Flags().Lookup("keyserver"))
	_ = viper.BindPFlag("master_key_path", cmd.Flags().Lookup("master-key-path"))
	_ = viper.BindPFlag("backup_dir", cmd.Flags().Lookup("backup-dir"))
	_ = viper.BindPFlag("no_color", cmd.Flags().Lookup("no-color"))
}

// getServices creates and returns service instances.
func getServices() (*gpg.Service, *yubikey.Service, *backup.Service) {
	exec := executor.NewRealExecutor()
	gpgSvc := gpg.NewService(exec)
	yubikeySvc := yubikey.NewService(gpgSvc, exec)
	backupSvc := backup.NewService(gpgSvc)
	return gpgSvc, yubikeySvc, backupSvc
}
