package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func resolveEncryptPassword(flagValue string) (string, error) {
	if strings.TrimSpace(flagValue) != "" {
		return flagValue, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no password provided and stdin is not an interactive terminal")
	}

	password, err := readPasswordPrompt("Encrypt password: ")
	if err != nil {
		return "", err
	}
	confirm, err := readPasswordPrompt("Retype password: ")
	if err != nil {
		return "", err
	}

	if password != confirm {
		return "", errors.New("passwords do not match")
	}

	return password, nil
}

func resolveDecryptPassword(flagValue string) (string, error) {
	if strings.TrimSpace(flagValue) != "" {
		return flagValue, nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no password provided and stdin is not an interactive terminal")
	}

	return readPasswordPrompt("Decrypt password: ")
}

func readPasswordPrompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	password := strings.TrimSpace(string(pw))
	if password == "" {
		return "", errors.New("password must not be empty")
	}

	return password, nil
}
