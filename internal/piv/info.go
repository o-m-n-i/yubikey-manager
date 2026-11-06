// Package piv wraps the PIV (smart card) side of a YubiKey: reading its state
// through ykman, preparing it for Vault certificate login, and signing the
// TLS handshake on the device.
//
// No PIN, PUK or management key ever passes through this package's command
// lines or logs. Steps that need one are run through ykman's own interactive
// prompts, or (for login) read from the terminal / pinentry and handed straight
// to the card.
package piv

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SlotAuth is the PIV slot used for Vault login (ykman notation).
const SlotAuth = "9a"

// SlotInfo describes one populated PIV slot as reported by `ykman piv info`.
type SlotInfo struct {
	Slot       string // upper-case, e.g. "9A"
	Name       string // e.g. "AUTHENTICATION"
	KeyType    string // e.g. "ECCP256"; empty when the slot holds no key
	Subject    string // certificate subject DN; empty when there is no certificate
	HasCert    bool
	NotBefore  string
	NotAfter   string
	CertSerial string
}

// Info is the parsed state of a YubiKey's PIV application.
type Info struct {
	Version string

	PINRetries int // -1 when unknown
	PUKRetries int

	DefaultPIN           bool
	DefaultPUK           bool
	DefaultManagementKey bool
	ManagementKeyAlgo    string
	ManagementKeyStored  bool // stored on the key, protected by the PIN

	Slots map[string]*SlotInfo // keyed by upper-case slot id
}

// Slot returns the populated slot with the given id (case-insensitive), or nil.
func (i *Info) Slot(id string) *SlotInfo {
	return i.Slots[strings.ToUpper(id)]
}

// KeyPolicy is the policy part of `ykman piv keys info`.
type KeyPolicy struct {
	Algorithm string
	Origin    string
	PIN       string // e.g. ONCE
	Touch     string // e.g. ALWAYS
}

var (
	reRetries = regexp.MustCompile(`^(PIN|PUK) tries remaining:\s*(\d+)/(\d+)`)
	reSlot    = regexp.MustCompile(`^Slot ([0-9A-Fa-f]{2}) \(([^)]*)\):`)
	reDefault = regexp.MustCompile(`(?i)using default (PIN|PUK|management key)`)
)

// ParseInfo parses the output of `ykman piv info`.
func ParseInfo(out string) (*Info, error) {
	info := &Info{PINRetries: -1, PUKRetries: -1, Slots: map[string]*SlotInfo{}}
	var cur *SlotInfo
	seenVersion := false

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, " \r\t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if m := reSlot.FindStringSubmatch(trimmed); m != nil && !strings.HasPrefix(line, " ") {
			cur = &SlotInfo{Slot: strings.ToUpper(m[1]), Name: m[2]}
			info.Slots[cur.Slot] = cur
			continue
		}
		if !strings.HasPrefix(line, " ") {
			cur = nil
		}

		if cur != nil {
			key, val, ok := splitKV(trimmed)
			if !ok {
				continue
			}
			switch key {
			case "Private key type":
				cur.KeyType = val
			case "Subject DN":
				cur.Subject, cur.HasCert = val, true
			case "Serial":
				cur.CertSerial = val
			case "Not before":
				cur.NotBefore = val
			case "Not after":
				cur.NotAfter = val
			}
			continue
		}

		if m := reRetries.FindStringSubmatch(trimmed); m != nil {
			n, _ := strconv.Atoi(m[2])
			if m[1] == "PIN" {
				info.PINRetries = n
			} else {
				info.PUKRetries = n
			}
			continue
		}
		if m := reDefault.FindStringSubmatch(trimmed); m != nil {
			switch strings.ToLower(m[1]) {
			case "pin":
				info.DefaultPIN = true
			case "puk":
				info.DefaultPUK = true
			default:
				info.DefaultManagementKey = true
			}
			continue
		}
		if key, val, ok := splitKV(trimmed); ok {
			switch key {
			case "PIV version":
				info.Version, seenVersion = val, true
			case "Management key algorithm":
				info.ManagementKeyAlgo = val
			}
			continue
		}
		if strings.HasPrefix(trimmed, "Management key is stored on the YubiKey") {
			info.ManagementKeyStored = true
		}
	}

	if !seenVersion {
		return nil, fmt.Errorf("unexpected `ykman piv info` output (no PIV version line)")
	}
	return info, nil
}

// ParseKeyInfo parses the output of `ykman piv keys info <slot>`.
func ParseKeyInfo(out string) (*KeyPolicy, error) {
	p := &KeyPolicy{}
	found := false
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := splitKV(strings.TrimSpace(line))
		if !ok {
			continue
		}
		switch key {
		case "Algorithm":
			p.Algorithm, found = val, true
		case "Origin":
			p.Origin = val
		case "PIN required for use":
			p.PIN = val
		case "Touch required for use":
			p.Touch = val
		}
	}
	if !found {
		return nil, fmt.Errorf("unexpected `ykman piv keys info` output")
	}
	return p, nil
}

func splitKV(line string) (key, val string, ok bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}
