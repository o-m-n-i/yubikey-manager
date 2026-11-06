# YubiKey GPG Manager

[![CI](https://github.com/bobbydams/yubikey-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/bobbydams/yubikey-manager/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/bobbydams/yubikey-manager/graph/badge.svg?token=3CRAXf35hS)](https://codecov.io/github/bobbydams/yubikey-manager)
[![Go Report Card](https://goreportcard.com/badge/github.com/bobbydams/yubikey-manager)](https://goreportcard.com/report/github.com/bobbydams/yubikey-manager)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/bobbydams/yubikey-manager.svg)](https://github.com/bobbydams/yubikey-manager/releases)

A robust Go CLI tool for managing GPG signing subkeys across multiple YubiKeys. This tool provides a safe and convenient way to set up, manage, and maintain GPG keys on YubiKey hardware security modules.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**IMPORTANT DISCLAIMER**: This software is provided "AS IS" without warranty of any kind. The authors assume no liability for any loss or corruption of GPG keys, damage to YubiKey devices, or any other consequences resulting from the use of this software. **Use at your own risk.** Always maintain secure backups of your master GPG keys and test operations in a safe environment before using on production keys or devices.

## Features

- **Setup New YubiKeys**: Add signing subkeys to new YubiKeys (interactive or semi-automated)
- **Revoke Compromised Keys**: Revoke subkeys when YubiKeys are lost or compromised
- **Extend Expiration**: Extend expiration dates on keys and subkeys
- **Key Management**: Clean up old/expired keys from your keyring
- **Backup Management**: Automatic backups before making changes
- **Status & Verification**: Check key and YubiKey status, verify setup
- **Vault break-glass login**: Prepare the PIV app of every YubiKey and log in to Vault with it (see [Vault break-glass login](#vault-break-glass-login))

## Installation

### Prerequisites

- Go 1.26 or later (see `go.mod`)
- GPG 2.2+ installed and configured
- YubiKey with OpenPGP support

### Build from Source

```bash
git clone https://github.com/bobbydams/yubikey-manager.git
cd yubikey-manager
go build -o ykgpg ./cmd/ykgpg
```

### Install

```bash
go install ./cmd/ykgpg
```

## Configuration

### Interactive Configuration Setup

The easiest way to set up configuration is using the interactive command:

```bash
ykgpg config init
```

This will prompt you for all required configuration values and create the config file at `~/.config/ykgpg/config.yaml`.

### Manual Configuration File

Alternatively, you can manually create a configuration file at `~/.config/ykgpg/config.yaml`:

```yaml
primary_key_id: "YOUR_KEY_ID_HERE"
primary_key_fingerprint: "YOUR_FULL_FINGERPRINT_HERE"
user_name: "Your Name"
user_email: "your.email@example.com"
keyserver: "hkps://keys.openpgp.org"
backup_dir: "~/.gnupg/backups"
no_color: false # Set to true to disable colored output
```

You can copy `config.example.yaml` as a starting point.

### Disable Colors

You can disable colored output in several ways:

- **CLI flag**: `ykgpg --no-color <command>`
- **Config file**: Set `no_color: true` in your config file
- **Environment variable**: `export YKGPG_NO_COLOR=true`

### View Current Configuration

To see your current configuration values from all sources:

```bash
ykgpg config show
```

This displays the effective configuration values, showing which sources (config file, environment variables, CLI flags) are being used.

### Environment Variables

All configuration values can be overridden with environment variables using the `YKGPG_` prefix:

```bash
export YKGPG_PRIMARY_KEY_ID="YOUR_KEY_ID_HERE"
export YKGPG_MASTER_KEY_PATH="/path/to/master/key.asc"
```

### CLI Flags

Configuration can also be set via CLI flags:

```bash
ykgpg status --key-id "YOUR_KEY_ID_HERE" --name "Your Name"
```

**Priority Order**: CLI flags > Environment variables > Config file > Defaults

## Usage

### Show Status

```bash
ykgpg status
```

Displays information about your primary key and connected YubiKey.

### Setup New YubiKey

**Interactive mode** (recommended for first-time setup):

```bash
ykgpg setup
```

**Semi-automated mode** (faster, but still requires some interaction):

```bash
ykgpg setup-batch
```

Both commands will:

1. Create a backup of your current keyring
2. Prompt for your master key backup
3. Generate a new signing subkey
4. Move the subkey to your YubiKey
5. Optionally remove the master key from your local machine
6. Optionally upload the updated key to a keyserver

### Revoke a Subkey

If a YubiKey is lost or compromised:

```bash
ykgpg revoke
```

This will:

1. Show all current signing subkeys
2. Prompt you to select which key to revoke
3. Create a backup
4. Import your master key
5. Guide you through the revocation process
6. Upload the revocation to the keyserver

### Extend Key Expiration

```bash
ykgpg extend
```

Extends the expiration date on your primary key and all subkeys.

### Clean Up Old Keys

```bash
ykgpg cleanup
```

Helps identify and remove old or expired keys from your keyring.

### Set YubiKey Metadata

```bash
ykgpg set-metadata
```

Sets the cardholder name and URL on your YubiKey for easier identification.

### Export Public Key

```bash
ykgpg export
ykgpg export --output /path/to/key.asc
```

Exports your public key for sharing or uploading to keyservers.

### Verify Setup

```bash
ykgpg verify
```

Checks that your GPG and YubiKey setup is correct, including:

- Primary key exists
- Master key is offline
- YubiKey is detected
- Git signing configuration
- GPG signing works

## Commands

| Command        | Description                                            |
| -------------- | ------------------------------------------------------ |
| `status`       | Show current key and YubiKey status                    |
| `init`         | Initialize a new YubiKey (PINs, key algorithms)        |
| `setup`        | Add a signing subkey to a new YubiKey (interactive)    |
| `setup-batch`  | Add a signing subkey to a new YubiKey (semi-automated) |
| `move-subkey`  | Move an existing signing subkey to a YubiKey           |
| `revoke`       | Revoke a subkey (for lost/compromised YubiKeys)        |
| `extend`       | Extend expiration dates on keys                        |
| `cleanup`      | Remove old/expired keys from keyring                   |
| `set-metadata` | Set cardholder name and URL on YubiKey                 |
| `export`       | Export public key to file                              |
| `verify`       | Verify GPG and YubiKey setup                           |
| `config init`  | Interactively generate configuration file              |
| `config show`  | Show current configuration values                      |
| `piv status`   | PIV state of each YubiKey and its Vault registration   |
| `piv setup`    | Prepare slot 9a, PIN, PUK and management key           |
| `piv register` | Register the slot 9a certificate as a Vault cert role  |
| `vault login`  | Log in to Vault with the YubiKey (saves `~/.vault-token`) |

## Vault break-glass login

On recent Vault versions the recovery keys alone no longer yield a root token:
`generate-root` needs a valid Vault token as well. When your usual login (SSO, OIDC) is down, the
only admin login left is the **YubiKey certificate login**, so every YubiKey
should be prepared for it. The `piv` and `vault` commands do that in one sitting.
They need no GPG configuration.

### What it is for

Slot 9a of the YubiKey's PIV application holds an ECCP256 key and a self-signed
certificate. The certificate is registered in Vault's cert auth method
(`auth/cert/certs/yubikey-<name>`, policy `yubikey-admin`, token TTL 8h, max 24h).
`ykgpg vault login` signs the TLS client handshake **on the YubiKey** (via
[piv-go](https://github.com/go-piv/piv-go)), so the private key never leaves the
device. The `vault` CLI and `curl` cannot do this login.

### From a blank key to a working login

```bash
ykgpg piv status                              # what state is each key in?
ykgpg piv setup    --name laptop-a --device 22222222
ykgpg piv register --name laptop-a --device 22222222   # needs an admin Vault token
ykgpg vault login  --device 22222222
```

1. `piv setup` generates the slot 9a key (`--pin-policy ONCE --touch-policy ALWAYS`)
   and the certificate `CN=yubikey-<name>` (10 years), replaces the factory PIN
   and PUK, and sets a random AES192 management key that is stored on the key and
   protected by the PIN. ykman asks for the PINs on the terminal; ykgpg never takes
   a PIN, PUK or management key as a flag and never logs one. Re-running it for the
   same `--name` skips the steps already done.
2. `piv register` writes the Vault role from the slot 9a certificate. It needs an
   admin token (`VAULT_TOKEN` or `~/.vault-token`) and network access to Vault, and refuses when a
   role already trusts that certificate or the role name is taken.
3. `vault login` saves the token to `~/.vault-token` (0600) and prints only the role,
   policies and TTL. The token is printed only with `--print-token`.

Role names are lower case: Vault 2.x matches ACL role names in lower case.

With several YubiKeys connected, every command refuses to act until you give
`--device <serial>` (`piv status` is the exception: it only reads, and lists them all).

### Which PIN is which

A YubiKey holds several separate secrets for separate applications. They do not
unlock each other, and ykman's prompts only say "PIN" or "PUK", so `ykgpg piv setup`
tells you before each step what every prompt wants.

| Secret | Application | Used for | Factory default | Touched by `ykgpg piv` |
| --- | --- | --- | --- | --- |
| **PIV PIN** (6-8 chars) | PIV | unlocking the certificate key: Vault login, smart-card login | `123456` | yes |
| **PIV PUK** (6-8 chars) | PIV | unblocking a blocked PIV PIN | `12345678` | yes |
| **PIV management key** | PIV | letting ykman change PIV settings; random, stored on the key, unlocked by the PIV PIN | `010203...` (public default) | yes |
| OpenPGP PIN | OpenPGP | GPG signing and decryption | `123456` | no |
| OpenPGP Admin PIN | OpenPGP | changing OpenPGP settings | `12345678` | no |
| FIDO2 PIN | FIDO2 | passkeys, security-key login | none | no |

The defaults of the PIV and OpenPGP PINs look identical, which is the usual source of
confusion. Typing the wrong one still costs a PIV attempt. `vault login` checks the
length before anything reaches the key and **refuses to try a PIN when only one attempt
is left**, so it cannot lock the PIV app. If the PIV PIN does get blocked, unblock it
with the PIV PUK: `ykman piv access unblock-pin`.

Using the same value for several of these is possible but weakens them: for example, if
the PIV PUK equals the PIV PIN, anyone who learns the PIN can also reset it.

### Slot 9a may be shared

On a key that already uses slot 9a (for example macOS smart-card pairing, or SSH
through yubikey-agent), regenerating the slot breaks all of that and the Vault
login at once. `piv setup` therefore refuses a slot 9a that holds a key unless you
pass `--force`, explains what would be lost, and then makes you type the serial
number. Run `ykgpg piv status` first.

### The scdaemon note

piv-go opens the smart card in exclusive mode. gpg's `scdaemon` keeps a connection
open, which shows up as *"the smart card cannot be accessed because of other
connections outstanding"*. `vault login` runs `gpgconf --kill scdaemon` first;
gpg-agent restarts it on demand, so signing commits straight afterwards still works.
`yubikey-agent` can hold the card the same way: ykgpg detects it and tells you, but
does not kill it. Stop it yourself and retry.

### Building

`vault login` needs cgo and the PC/SC framework (built into macOS; `libpcsclite-dev`
on Linux). Build it where the YubiKey is: `go install ./cmd/ykgpg` on the Mac.
The prebuilt release binaries are cross-compiled without cgo; `piv status`,
`piv setup` and `piv register` (which use ykman) work in them, `vault login` says it
needs a build from source.

Requirements: `ykman` for `piv *`; `pinentry-mac` for PIN entry when there is no terminal.

## Troubleshooting

### PIN Issues

**YubiKey has TWO separate PINs for OpenPGP:**
| PIN Type | Default | Min Length | Used For |
|----------|---------|------------|----------|
| User PIN | 123456 | 6 chars | Signing, decrypting |
| Admin PIN | 12345678 | 8 chars | Card management, moving keys |

**Important:** These are NOT the same as YubiKey Authenticator or FIDO2 PINs!

**To change PINs:**
```bash
gpg --card-edit
gpg/card> admin
gpg/card> passwd
# Select (1) for User PIN, (3) for Admin PIN
# Enter CURRENT pin first, then NEW pin
```

**If PIN is locked** (retry counter = 0):
```bash
gpg --card-edit
gpg/card> admin
gpg/card> passwd
# Select (1) change PIN
# Enter Admin PIN to unlock and set new User PIN
```

### Pinentry Issues

If PIN prompts don't appear or hang, switch to terminal-based pinentry:
```bash
# Add to ~/.gnupg/gpg-agent.conf:
pinentry-program /opt/homebrew/bin/pinentry-curses

# Then restart agent:
gpgconf --kill gpg-agent
export GPG_TTY=$(tty)
```

### Key Type Mismatch (RSA vs ECC)

If `keytocard` silently fails and `save` says "Key not changed":
```bash
gpg --card-status | grep "Key attributes"
```

If it shows `rsa2048` but your key is `ed25519`, configure the card first:
```bash
gpg --card-edit
gpg/card> admin
gpg/card> key-attr
# Select (2) ECC, then (1) Curve 25519 for each slot
```

### Lost Key After Factory Reset

**Symptoms:** `gpg --list-secret-keys` shows `ssb#` (# = no secret key available)

**Cause:** `keytocard` MOVES keys (doesn't copy). If you factory reset the card without a backup, the key is lost.

**Prevention:** Always backup AFTER creating new subkeys:
```bash
gpg --export-secret-keys YOUR_KEY_ID > master-key-backup.gpg
```

**Recovery:** If you have a backup:
```bash
gpg --import /path/to/master-key-backup.gpg
```

**If no backup exists:** Create a new subkey:
```bash
gpg --edit-key YOUR_KEY_ID
gpg> addkey
# Select (10) ECC (sign only), (1) Curve 25519, set expiration
gpg> save
```

### Key Stub Issues

After factory reset, GPG may still think keys are on the card. To clear:
```bash
# Delete the orphaned stub
gpg --delete-secret-keys SUBKEY_ID

# Re-import from backup
gpg --import /path/to/backup.gpg
```

### GPG Hanging

If GPG commands hang:
```bash
# Kill hanging processes and restart agent
pkill -9 gpg
gpgconf --kill gpg-agent
```

## Development

### Running Tests

**Unit tests** (with mocked dependencies):

```bash
go test ./...
```

**Integration tests** (requires GPG and optionally a YubiKey):

```bash
go test -tags=integration ./...
```

### Project Structure

```
yubikey-manager/
├── cmd/ykgpg/          # CLI entry point
├── internal/
│   ├── cli/            # CLI commands
│   ├── gpg/            # GPG service and parsers
│   ├── yubikey/        # YubiKey service
│   ├── backup/         # Backup service
│   ├── config/         # Configuration management
│   └── executor/       # Command execution abstraction
├── pkg/ui/             # UI helpers (output, prompts)
└── testdata/           # Test fixtures
```

## Security Considerations

- **Master Key Safety**: The master key should never be stored on your regular machine. Always use a secure backup (USB drive, encrypted storage).
- **Backups**: The tool automatically creates backups before making changes. Keep these backups secure.
- **Key Revocation**: Revoked keys cannot be un-revoked. Be certain before revoking a key.
- **YubiKey PINs**: Keep your YubiKey PINs secure and use strong PINs.

## Contributing

Contributions are welcome! Please open an issue or pull request.

## Acknowledgments

This tool was converted from a Bash script to provide better testability, maintainability, and cross-platform support.
