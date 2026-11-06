package piv

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// PromptPIN asks for the PIV PIN: on /dev/tty when there is one, otherwise in
// a pinentry-mac dialog (what GPG uses), so it also works from an editor or an
// agent session. The prompt always says this is the PIV PIN, because the OpenPGP
// app has its own PIN and Admin PIN and typing those here only burns attempts.
func PromptPIN(purpose string, retries int) (string, error) {
	prompt := fmt.Sprintf("YubiKey PIV PIN for %s (%d attempts left; not your GPG PIN): ", purpose, retries)
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer func() { _ = tty.Close() }()
		fmt.Fprint(tty, prompt)
		pin, err := term.ReadPassword(int(tty.Fd()))
		_, _ = fmt.Fprintln(tty)
		if err == nil {
			return CheckPIN(string(pin))
		}
	}
	return pinentry(purpose, prompt)
}

func pinentry(title, prompt string) (string, error) {
	bin, err := exec.LookPath("pinentry-mac")
	if err != nil {
		return "", errors.New("no terminal and pinentry-mac not found (brew install pinentry-mac)")
	}
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(pinentryScript(title, prompt))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("pinentry-mac: %w", err)
	}
	pin, err := parsePinentry(out)
	if err != nil {
		return "", err
	}
	return CheckPIN(pin)
}

// pinentryScript builds the Assuan commands; the text is percent-escaped as the
// protocol requires.
func pinentryScript(title, prompt string) string {
	esc := strings.NewReplacer("%", "%25", "\n", "%0A", "\r", "%0D", " ", "%20")
	return "SETTITLE " + esc.Replace(title) + "\nSETDESC " + esc.Replace(prompt) +
		"\nSETPROMPT PIV%20PIN:\nGETPIN\nBYE\n"
}

// parsePinentry extracts the PIN from pinentry's Assuan reply.
func parsePinentry(out []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "D ") {
			return url.PathUnescape(strings.TrimPrefix(line, "D "))
		}
		if strings.HasPrefix(line, "ERR") {
			break
		}
	}
	return "", errors.New("PIN entry cancelled")
}

// CheckPIN rejects input that cannot be a PIV PIN before it costs an attempt.
func CheckPIN(pin string) (string, error) {
	if len(pin) < 6 || len(pin) > 8 {
		return "", errors.New("a PIV PIN is 6-8 characters; nothing was sent to the YubiKey")
	}
	return pin, nil
}
