package piv

import (
	"fmt"
	"strconv"
	"strings"
)

// ResolveSerial picks the YubiKey to act on. With no wanted serial it requires
// exactly one connected key; with one, it must be among the connected keys.
// Refusing to guess keeps a PIN prompt from ever reaching the wrong key.
func ResolveSerial(connected []string, wanted string) (string, error) {
	wanted = strings.TrimSpace(wanted)
	if wanted != "" {
		if _, err := strconv.Atoi(wanted); err != nil {
			return "", fmt.Errorf("--device must be a YubiKey serial number, got %q", wanted)
		}
		for _, s := range connected {
			if s == wanted {
				return s, nil
			}
		}
		return "", fmt.Errorf("YubiKey %s is not connected (connected: %s)", wanted, describe(connected))
	}
	switch len(connected) {
	case 0:
		return "", fmt.Errorf("no YubiKey found; insert it and try again")
	case 1:
		return connected[0], nil
	default:
		return "", fmt.Errorf("%d YubiKeys connected (%s); pick one with --device <serial>", len(connected), describe(connected))
	}
}

func describe(serials []string) string {
	if len(serials) == 0 {
		return "none"
	}
	return strings.Join(serials, ", ")
}
