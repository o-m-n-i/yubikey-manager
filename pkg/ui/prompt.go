package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Confirm prompts the user for a yes/no confirmation.
// Returns true if the user responds with 'y' or 'yes' (case-insensitive).
// Returns false for any other response or empty input.
func Confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	os.Stdout.Sync()

	fd := int(os.Stdin.Fd())

	// If not a terminal, use simple bufio reading
	if !term.IsTerminal(fd) {
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		response = strings.TrimSpace(strings.ToLower(response))
		response = strings.TrimRight(response, "\r")
		return response == "y" || response == "yes"
	}

	// For terminals, use raw mode to have full control over input
	// This prevents issues like ^M (carriage return) being displayed
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		// Fallback to bufio if raw mode fails
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		response = strings.TrimSpace(strings.ToLower(response))
		response = strings.TrimRight(response, "\r")
		return response == "y" || response == "yes"
	}
	defer term.Restore(fd, oldState)

	// Read characters one by one until newline
	var response strings.Builder
	for {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if err != nil || n == 0 {
			break
		}

		// Handle Enter key - break on \n or \r
		if b[0] == '\n' || b[0] == '\r' {
			break
		}

		// Handle Ctrl+C
		if b[0] == 3 {
			term.Restore(fd, oldState)
			fmt.Println()
			os.Exit(130)
		}

		// Handle backspace/delete
		if b[0] == 127 || b[0] == 8 {
			if response.Len() > 0 {
				str := response.String()
				response.Reset()
				response.WriteString(str[:len(str)-1])
				fmt.Print("\b \b")
			}
			continue
		}

		// Handle printable characters
		if b[0] >= 32 {
			response.WriteByte(b[0])
			fmt.Print(string(b[0]))
		}
	}

	fmt.Println() // Move to next line after input

	responseStr := strings.TrimSpace(strings.ToLower(response.String()))
	return responseStr == "y" || responseStr == "yes"
}

// Prompt reads a line of input from the user.
// Returns the trimmed input string.
func Prompt(prompt string) (string, error) {
	fmt.Print(prompt)
	os.Stdout.Sync()

	fd := int(os.Stdin.Fd())

	// If not a terminal, use simple bufio reading
	if !term.IsTerminal(fd) {
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}
		return strings.TrimSpace(strings.TrimRight(response, "\r")), nil
	}

	// For terminals, use raw mode to have full control over input
	// This prevents issues like ^M (carriage return) being displayed
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		// Fallback to bufio if raw mode fails
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}
		return strings.TrimSpace(strings.TrimRight(response, "\r")), nil
	}
	defer term.Restore(fd, oldState)

	// Read characters one by one until newline
	var response strings.Builder
	for {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if err != nil || n == 0 {
			break
		}

		// Handle Enter key - on macOS/Unix, Enter sends \r; on Windows it's \r\n
		// Break on either \r or \n to handle both cases
		if b[0] == '\n' {
			break
		}
		if b[0] == '\r' {
			// On macOS/Unix, \r is Enter; on Windows, \r\n is Enter
			// Check if there's a \n immediately following (Windows case)
			// For now, just break on \r to handle macOS/Unix case
			break
		}

		// Handle Ctrl+C
		if b[0] == 3 {
			term.Restore(fd, oldState)
			fmt.Println()
			os.Exit(130)
		}

		// Handle backspace/delete
		if b[0] == 127 || b[0] == 8 {
			if response.Len() > 0 {
				// Remove last character from buffer
				str := response.String()
				response.Reset()
				response.WriteString(str[:len(str)-1])
				// Erase character on screen
				fmt.Print("\b \b")
			}
			continue
		}

		// Handle printable characters
		if b[0] >= 32 {
			response.WriteByte(b[0])
			fmt.Print(string(b[0]))
		}
	}

	fmt.Println() // Move to next line after input

	return strings.TrimSpace(response.String()), nil
}

// PromptRequired reads a line of input from the user and ensures it's not empty.
// Continues prompting until a non-empty response is provided.
func PromptRequired(prompt string) (string, error) {
	for {
		response, err := Prompt(prompt)
		if err != nil {
			return "", err
		}

		if response != "" {
			return response, nil
		}

		LogWarning("This field is required. Please enter a value.")
	}
}
