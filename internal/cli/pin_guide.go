package cli

import (
	"fmt"

	"github.com/bobbydams/yubikey-manager/pkg/ui"
)

// A YubiKey holds several separate secrets, and ykman's own prompts only say
// "PIN" or "PUK". These helpers name each one the same way everywhere, and tell
// the user what each upcoming prompt wants before ykman asks it.

// Names used for the secrets, in every message.
const (
	namePIVPIN  = "PIV PIN"
	namePIVPUK  = "PIV PUK"
	namePIVMgmt = "PIV management key"
)

// printSecretsOverview lists every secret on a YubiKey and which ones the
// command touches.
func printSecretsOverview() {
	ui.PrintSection("WHICH PIN IS WHICH")
	fmt.Println("  A YubiKey keeps these secrets separately. They do not unlock each other.")
	fmt.Println()
	fmt.Println("  Touched by this command (the PIV application):")
	fmt.Println("    PIV PIN             6-8 chars. Unlocks the certificate key: Vault login, smart-card login.")
	fmt.Println("                        Factory default: 123456")
	fmt.Println("    PIV PUK             6-8 chars. Only used to unblock a blocked PIV PIN.")
	fmt.Println("                        Factory default: 12345678")
	fmt.Println("    PIV management key  Lets ykman change PIV settings. Set to a random value stored on")
	fmt.Println("                        the key and unlocked by the PIV PIN; you never type or keep it.")
	fmt.Println()
	fmt.Println("  NOT touched here (other applications on the same YubiKey):")
	fmt.Println("    OpenPGP PIN         GPG signing and decryption")
	fmt.Println("    OpenPGP Admin PIN   changing OpenPGP settings")
	fmt.Println("    FIDO2 PIN           passkeys and security-key login")
	fmt.Println()
}

// printPromptGuide shows what the next ykman prompts will ask for, in order.
func printPromptGuide(title string, lines ...string) {
	ui.LogInfo("%s", title)
	fmt.Println("  ykman will ask, in this order:")
	for _, l := range lines {
		fmt.Println("    -", l)
	}
	fmt.Println()
}

func pivPINAnswer(isDefault bool) string {
	if isDefault {
		return `"Enter PIN" -> the ` + namePIVPIN + `: the factory default 123456`
	}
	return `"Enter PIN" -> your ` + namePIVPIN
}

const mgmtAnswer = `"Enter a management key [blank to use default key]" -> just press Enter (leave it empty)`
