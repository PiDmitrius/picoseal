// picoseal seals secrets into libsodium sealed boxes (crypto_box_seal): anyone
// may wrap with the public key, only the owner of the private key may open.
// The binary carries no key material and is safe to copy; the private key is
// protected by file permissions alone. Never grant an unprivileged caller access
// to open or env — an oracle that decrypts any record is the key itself.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/unix"
)

const (
	version = "v0.1.0"
	// maxValue caps a piped secret; a terminal line is capped by the canonical
	// buffer of the tty driver, which discards the rest without telling anyone.
	maxValue    = 64 << 10
	maxTerminal = 4095
)

var (
	keyDirPath = "/etc/picoseal"
	nameRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	errUsage   = errors.New("usage")
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "wrap":
		err = cmdWrap(os.Args[2:])
	case "open":
		err = cmdOpen(os.Args[2:])
	case "env":
		err = cmdEnv(os.Args[2:])
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
	fmt.Fprintf(os.Stderr, `picoseal %s — sealed secrets for fixed admin jobs

Unprivileged:
  wrap                        Seal a secret to stdout: one unechoed line from a
                              terminal (under %d bytes), or a pipe as it is, up
                              to %d bytes, with one trailing newline stripped

Private key holder only:
  keygen                      Create the key pair in %s
  open <file>                 Print the secret (refuses a terminal)
  env NAME=<file> [...] -- /abs/cmd [args]
                              Run cmd with the secrets in its environment

A record is one line of unpadded base64url. Every open is logged to syslog as
authpriv.notice.
`, version, maxTerminal, maxValue, keyDirPath)
}

func keyPath() string { return filepath.Join(keyDirPath, "key") }
func pubPath() string { return filepath.Join(keyDirPath, "key.pub") }

func readKey(path string) (*[32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%s: not a picoseal key", path)
	}
	var key [32]byte
	copy(key[:], raw)
	return &key, nil
}

// audit fails closed: a release nobody can account for must not happen.
func audit(path string, err error) error {
	result := "ok"
	if err != nil {
		result = "error"
	}
	w, logErr := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE, "picoseal")
	if logErr != nil {
		return fmt.Errorf("audit unavailable: %w", logErr)
	}
	defer w.Close()
	line := fmt.Sprintf("uid=%d caller=%q record=%q result=%s", os.Getuid(), os.Getenv("SUDO_USER"), path, result)
	if logErr := w.Notice(line); logErr != nil {
		return fmt.Errorf("audit unavailable: %w", logErr)
	}
	return err
}

func cmdKeygen(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	pub, secret, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	priv, err := os.OpenFile(keyPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("private key not created: %w", err)
	}
	defer priv.Close()
	done := false
	defer func() {
		if !done {
			os.Remove(keyPath())
		}
	}()

	pubFile, err := os.OpenFile(pubPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("public key not created: %w", err)
	}
	defer pubFile.Close()
	defer func() {
		if !done {
			os.Remove(pubPath())
		}
	}()
	if _, err := io.WriteString(priv, base64.RawURLEncoding.EncodeToString(secret[:])+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(pubFile, base64.RawURLEncoding.EncodeToString(pub[:])+"\n"); err != nil {
		return err
	}
	if err := pubFile.Chmod(0o644); err != nil {
		return err
	}
	done = true
	fmt.Printf("key created in %s\n", keyDirPath)
	return nil
}

func cmdWrap(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	pub, err := readKey(pubPath())
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
	_, err = fmt.Println(base64.RawURLEncoding.EncodeToString(sealed))
	return err
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
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
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
		return nil, fmt.Errorf("a terminal drops anything past %d bytes; pipe longer secrets", maxTerminal)
	}
	return []byte(line), nil
}

func unseal(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(sealed) < box.AnonymousOverhead {
		return nil, fmt.Errorf("%s: not a picoseal record", path)
	}
	priv, err := readKey(keyPath())
	if err != nil {
		return nil, err
	}
	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var pub [32]byte
	copy(pub[:], derived)
	value, ok := box.OpenAnonymous(nil, sealed, &pub, priv)
	if !ok {
		return nil, fmt.Errorf("%s: not a record for this key", path)
	}
	return value, nil
}

func cmdOpen(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	if _, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS); err == nil {
		return errors.New("refusing to write a secret to a terminal")
	}
	value, err := unseal(args[0])
	if err := audit(args[0], err); err != nil {
		return err
	}
	_, err = os.Stdout.Write(value)
	return err
}

func cmdEnv(args []string) error {
	var bindings [][2]string
	for len(args) > 0 && args[0] != "--" {
		name, path, found := strings.Cut(args[0], "=")
		if !found || !nameRe.MatchString(name) {
			return fmt.Errorf("bad assignment %q: expected NAME=<file>", args[0])
		}
		bindings = append(bindings, [2]string{name, path})
		args = args[1:]
	}
	if len(bindings) == 0 || len(args) < 2 {
		return errUsage
	}
	command := args[1]
	if !filepath.IsAbs(command) {
		return fmt.Errorf("%s: command must be an absolute path", command)
	}
	env := os.Environ()
	for _, b := range bindings {
		value, err := unseal(b[1])
		if err == nil && bytes.IndexByte(value, 0) >= 0 {
			err = errors.New("secret holds a NUL byte and cannot pass through the environment")
		}
		if err := audit(b[1], err); err != nil {
			return err
		}
		env = append(without(env, b[0]), b[0]+"="+string(value))
	}
	return syscall.Exec(command, args[1:], env)
}

func without(env []string, name string) []string {
	kept := env[:0]
	for _, entry := range env {
		if !strings.HasPrefix(entry, name+"=") {
			kept = append(kept, entry)
		}
	}
	return kept
}
