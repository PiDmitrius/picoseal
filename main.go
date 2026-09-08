// picoseal seals secrets into libsodium sealed boxes (crypto_box_seal). The
// binary carries no key material and is safe to copy; the private key and the
// records are protected by file permissions alone, so only root reads a secret
// and scripts an administrator has pinned are the only way an unprivileged
// caller reaches one. Never pin picoseal itself: open with a name of the caller's
// choosing is the key.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/unix"
)

const (
	// maxValue caps a piped secret; a terminal line is capped by the canonical
	// buffer of the tty driver, which discards the rest without telling anyone.
	maxValue    = 64 << 10
	maxTerminal = 4095
	binPath     = "/usr/local/bin/picoseal"
	defaultDir  = "/etc/picoseal"
)

var (
	dir      = defaultDir
	nameRe   = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	errUsage = errors.New("usage")
)

func main() {
	args := os.Args[1:]
	if len(args) >= 2 && args[0] == "--dir" {
		dir = args[1]
		args = args[2:]
	}
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	var err error
	switch args[0] {
	case "install":
		err = cmdInstall(args[1:])
	case "add":
		err = cmdAdd(args[1:])
	case "open":
		err = cmdOpen(args[1:])
	case "list":
		err = cmdList(args[1:])
	case "remove":
		err = cmdRemove(args[1:])
	default:
		usage()
		os.Exit(1)
	}
	if errors.Is(err, errUsage) {
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "picoseal: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `picoseal — sealed secrets for root scripts

  install          Create %s with secrets/ and scripts/, the key if there is
                   none, and %s
  add <name>       Seal stdin under <name>: one unechoed line from a terminal,
                   under %d bytes, or a whole pipe, up to %d bytes counting the
                   one trailing newline it strips
  open <name>      Print the secret
  list             List names
  remove <name>    Delete a secret

  --dir <path>     Use another directory instead of %s

All commands need root.
`, dir, binPath, maxTerminal, maxValue, defaultDir)
}

func keyPath() string { return filepath.Join(dir, "key") }

func secretPath(name string) (string, error) {
	if !nameRe.MatchString(name) || name == "." || name == ".." {
		return "", errors.New("name must match [a-z0-9._-]{1,64}")
	}
	return filepath.Join(dir, "secrets", name), nil
}

func keys() (pub, priv *[32]byte, err error) {
	data, err := os.ReadFile(keyPath())
	if err != nil {
		return nil, nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != 32 {
		return nil, nil, fmt.Errorf("%s: not a picoseal key", keyPath())
	}
	var secret, public [32]byte
	copy(secret[:], raw)
	derived, err := curve25519.X25519(secret[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	copy(public[:], derived)
	return &public, &secret, nil
}

func cmdInstall(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(dir, "scripts"), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	if err := ensureKey(); err != nil {
		return err
	}
	return installBinary()
}

func ensureKey() error {
	_, secret, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	err = writeNew(keyPath(), base64.RawURLEncoding.EncodeToString(secret[:])+"\n")
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Printf("key created in %s\n", dir)
	return nil
}

// writeNew creates path or leaves nothing behind.
func writeNew(path, data string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

// fsyncDir makes the new directory entry durable, not just the bytes in it.
func fsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func installBinary() error {
	self, err := os.Executable()
	if err != nil || self == binPath {
		return err
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	staged := binPath + ".new"
	if err := os.WriteFile(staged, data, 0o755); err != nil {
		return fmt.Errorf("%s not installed: %w", binPath, err)
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return err
	}
	if err := os.Rename(staged, binPath); err != nil {
		return err
	}
	fmt.Printf("installed %s\n", binPath)
	return nil
}

func cmdAdd(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	path, err := secretPath(args[0])
	if err != nil {
		return err
	}
	pub, _, err := keys()
	if err != nil {
		return err
	}
	value, err := readSecret()
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return errors.New("empty secret")
	}
	sealed, err := box.SealAnonymous(nil, value, pub, rand.Reader)
	if err != nil {
		return err
	}
	if err := writeNew(path, base64.RawURLEncoding.EncodeToString(sealed)+"\n"); err != nil {
		return fmt.Errorf("%s not stored: %w", args[0], err)
	}
	return nil
}

// readSecret takes the secret off a pipe as it is, and off a terminal without
// echoing it.
func readSecret() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		piped, err := io.ReadAll(io.LimitReader(os.Stdin, maxValue+1))
		if err != nil {
			return nil, err
		}
		if len(piped) > maxValue {
			return nil, fmt.Errorf("secret exceeds %d bytes", maxValue)
		}
		return []byte(strings.TrimSuffix(string(piped), "\n")), nil
	}

	quiet := *termios
	quiet.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETSF, &quiet); err != nil {
		return nil, err
	}
	restore := func() { _ = unix.IoctlSetTermios(fd, unix.TCSETSF, termios) }
	defer restore()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, unix.SIGTERM)
	defer signal.Stop(interrupt)
	go func() {
		<-interrupt
		restore()
		os.Exit(1)
	}()

	fmt.Fprint(os.Stderr, "Secret: ")
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, maxTerminal+1)).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && err != io.EOF {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) >= maxTerminal {
		return nil, fmt.Errorf("a terminal line of %d bytes or more may be cut; pipe it instead", maxTerminal)
	}
	return []byte(line), nil
}

func cmdOpen(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	value, err := unseal(args[0])
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(value)
	return err
}

func unseal(name string) ([]byte, error) {
	path, err := secretPath(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(sealed) < box.AnonymousOverhead {
		return nil, fmt.Errorf("%s: not a picoseal record", path)
	}
	pub, priv, err := keys()
	if err != nil {
		return nil, err
	}
	value, ok := box.OpenAnonymous(nil, sealed, pub, priv)
	if !ok {
		return nil, fmt.Errorf("%s: not a record for this key", path)
	}
	return value, nil
}

func cmdList(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	entries, err := os.ReadDir(filepath.Join(dir, "secrets"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Println(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func cmdRemove(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	path, err := secretPath(args[0])
	if err != nil {
		return err
	}
	return os.Remove(path)
}
