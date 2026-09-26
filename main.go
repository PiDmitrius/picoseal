// picoseal keeps secrets for root scripts in memory that never swaps: System V
// segments locked with SHM_LOCK, one per secret plus one for the session key E,
// owned by the caller with mode 0600 and scoped to its euid and store
// directory. A slot is a sealed box (crypto_box_seal) for E, and E lives until
// reboot. A store whose directory holds an unseal file also keeps every secret
// on disk, sealed for U, which Argon2id derives from a password salted with the
// store key; U exists only inside unseal, which loads those records into slots.
// export and import carry a stream sealed for another E and touch no store.
// A running picoseal holds its working copies in ordinary process memory, not
// dumpable, for as long as the command takes.
// Permissions are the whole boundary: only root reads root's secrets, and
// scripts an administrator has pinned are the only way an unprivileged caller
// reaches one. Never pin picoseal itself: open with a name of the caller's
// choosing is the key.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/unix"
)

const (
	// maxValue caps a piped secret; a terminal line is capped by the canonical
	// buffer of the tty driver, which discards the rest without telling anyone.
	maxValue    = 64 << 10
	maxTerminal = 4095
	maxRecord   = (maxValue+box.AnonymousOverhead+2)/3*4 + 1
	binPath     = "/usr/local/bin/picoseal"
	defaultDir  = "/etc/picoseal"
)

var (
	// dir is the store; empty means memory only, the default for non-root.
	dir         string
	nameRe      = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	errUsage    = errors.New("usage")
	errNoStore  = errors.New("no store: pass --dir")
	argonMemory = uint32(1 << 20)
)

func main() {
	unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	args := os.Args[1:]
	if os.Geteuid() == 0 {
		dir = defaultDir
	}
	if len(args) >= 2 && args[0] == "--dir" {
		abs, err := filepath.Abs(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "picoseal: "+err.Error())
			os.Exit(1)
		}
		dir = abs
		args = args[2:]
	}
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	commands := map[string]func([]string) error{
		"install": cmdInstall,
		"unseal":  cmdUnseal,
		"seal":    cmdSeal,
		"add":     cmdAdd,
		"open":    cmdOpen,
		"list":    cmdList,
		"remove":  cmdRemove,
		"pubkey":  cmdPubkey,
		"export":  cmdExport,
		"import":  cmdImport,
	}
	command, ok := commands[args[0]]
	if !ok {
		usage()
		os.Exit(1)
	}
	err := command(args[1:])
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

Secrets live in locked memory until reboot or seal. A store with an unseal
password also keeps them on disk and reloads them on unseal.

  install          Create the store %s with secrets/ and scripts/ and its
                   key; as root also copy the binary to %s
  unseal           Ask the store password, the first time twice, and load the
                   secrets on disk into memory
  seal             Drop every secret from memory
  add <name>       Keep stdin as <name>, on disk too if the store is unsealed
                   once: one unechoed line from a terminal, under %d bytes, or
                   a whole pipe, up to %d bytes counting the one trailing
                   newline it strips
  open <name>      Print the secret
  list             List names; "sealed" marks those on disk only
  remove <name>    Delete a secret from memory and disk
  pubkey           Print the session public key
  export <pubkey>  Seal stdin the same way for the session with <pubkey> and
                   print the record
  import           Print the stream in a record on stdin, as export prints it

  --dir <path>     Use the store at <path>; root uses %s by default,
                   everyone else keeps secrets in memory only

Only root reads root's secrets.
`, storeName(), binPath, maxTerminal, maxValue, defaultDir)
}

func storeName() string {
	if dir == "" {
		return "given by --dir"
	}
	return dir
}

func keyPath() string    { return filepath.Join(dir, "key") }
func markerPath() string { return filepath.Join(dir, "unseal") }

func checkName(name string) error {
	if !nameRe.MatchString(name) || name == "." || name == ".." {
		return errors.New("name must match [a-z0-9._-]{1,64}")
	}
	return nil
}

func secretPath(name string) string { return filepath.Join(dir, "secrets", name) }

func parseKey(s string) (*[32]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		return nil, false
	}
	var key [32]byte
	copy(key[:], raw)
	return &key, true
}

func encodeKey(key *[32]byte) string {
	return base64.RawURLEncoding.EncodeToString(key[:]) + "\n"
}

func readKey(path string) (*[32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, ok := parseKey(string(data))
	if !ok {
		return nil, fmt.Errorf("%s: not a picoseal key", path)
	}
	return key, nil
}

// storeKey returns the public U of an unsealed-once store, or nil.
func storeKey() (*[32]byte, error) {
	if dir == "" {
		return nil, nil
	}
	pub, err := readKey(markerPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return pub, err
}

func seal(pub *[32]byte, value []byte) (string, error) {
	sealed, err := box.SealAnonymous(nil, value, pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed) + "\n", nil
}

func openRecord(data []byte, source string, pub, priv *[32]byte) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(sealed) <= box.AnonymousOverhead {
		return nil, fmt.Errorf("%s: not a picoseal record", source)
	}
	value, ok := box.OpenAnonymous(nil, sealed, pub, priv)
	if !ok {
		return nil, fmt.Errorf("%s: not a record for this key", source)
	}
	return value, nil
}

func cmdInstall(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	if dir == "" {
		return errNoStore
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
	if os.Geteuid() != 0 {
		return nil
	}
	return installBinary()
}

func ensureKey() error {
	_, secret, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	err = writeNew(keyPath(), encodeKey(secret))
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

// deriveU turns the store password into U; the store key salts it, so the
// password alone opens nothing and the same password differs across stores.
func deriveU(password []byte) (pub, priv *[32]byte, err error) {
	key, err := readKey(keyPath())
	if err != nil {
		return nil, nil, err
	}
	if limit, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		if max, err := strconv.ParseUint(strings.TrimSpace(string(limit)), 10, 64); err == nil && max < uint64(argonMemory)<<10+64<<20 {
			return nil, nil, fmt.Errorf("unseal needs %d MiB of memory, the cgroup allows %d MiB", argonMemory>>10+64, max>>20)
		}
	}
	salt := sha256.Sum256(append([]byte("picoseal unseal\x00"), key[:]...))
	priv = new([32]byte)
	copy(priv[:], argon2.IDKey(password, salt[:], 3, argonMemory, 1, 32))
	return publicKey(priv), priv, nil
}

func cmdUnseal(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	if dir == "" {
		return errNoStore
	}
	marker, err := storeKey()
	if err != nil {
		return err
	}
	var password []byte
	if marker == nil {
		if !isTerminal() {
			return errors.New("the first unseal sets the password and needs a terminal to confirm it")
		}
		if password, err = readSecret("Password"); err != nil {
			return err
		}
		again, err := readSecret("Password again")
		if err != nil {
			return err
		}
		if string(again) != string(password) {
			return errors.New("passwords differ")
		}
	} else if password, err = readSecret("Password"); err != nil {
		return err
	}
	return unseal(password, marker)
}

// unseal checks password against the store's public U, or sets it when marker
// is nil, loads every record on disk that is not in a slot yet and stores on
// disk every slot that is not there yet.
func unseal(password []byte, marker *[32]byte) error {
	pub, priv, err := deriveU(password)
	if err != nil {
		return err
	}
	defer clear(priv[:])
	if marker == nil {
		if err := writeNew(markerPath(), encodeKey(pub)); err != nil {
			return err
		}
	} else if *pub != *marker {
		return errors.New("wrong password")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "secrets"))
	if err != nil {
		return err
	}
	loaded, err := slots()
	if err != nil {
		return err
	}
	var failed []error
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := loaded[name]; ok {
			continue
		}
		data, err := os.ReadFile(secretPath(name))
		if err == nil {
			var value []byte
			if value, err = openRecord(data, secretPath(name), pub, priv); err == nil {
				err = storeSlot(name, value)
			}
		}
		if err != nil {
			failed = append(failed, err)
		}
	}
	for name := range loaded {
		if _, err := os.Stat(secretPath(name)); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		value, err := loadSlot(name)
		if err == nil {
			var record string
			if record, err = seal(pub, value); err == nil {
				err = writeNew(secretPath(name), record)
			}
		}
		if err != nil {
			failed = append(failed, fmt.Errorf("%s not stored: %w", name, err))
		}
	}
	return errors.Join(failed...)
}

func cmdSeal(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	loaded, err := slots()
	if err != nil {
		return err
	}
	for _, id := range loaded {
		if err := removeSegment(id); err != nil {
			return err
		}
	}
	return nil
}

func cmdAdd(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	name := args[0]
	if err := checkName(name); err != nil {
		return err
	}
	store, err := storeKey()
	if err != nil {
		return err
	}
	if _, _, err := findSlot(name); err == nil {
		return fmt.Errorf("%s %w", name, errExists)
	}
	value, err := readSecret("Secret")
	if err != nil {
		return err
	}
	if store != nil {
		record, err := seal(store, value)
		if err != nil {
			return err
		}
		if err := writeNew(secretPath(name), record); err != nil {
			return fmt.Errorf("%s not stored: %w", name, err)
		}
	}
	if err := storeSlot(name, value); err != nil {
		// A concurrent unseal may have loaded the record just written.
		if loaded, loadErr := loadSlot(name); store != nil && errors.Is(err, errExists) && loadErr == nil && bytes.Equal(loaded, value) {
			return nil
		}
		if store != nil {
			os.Remove(secretPath(name))
		}
		return err
	}
	if store != nil {
		return nil
	}
	// A first unseal may have run since, without seeing this slot.
	if store, err = storeKey(); store == nil || err != nil {
		return err
	}
	record, err := seal(store, value)
	if err == nil {
		if err = writeNew(secretPath(name), record); errors.Is(err, os.ErrExist) {
			err = nil
		}
	}
	return err
}

func cmdOpen(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	if err := checkName(args[0]); err != nil {
		return err
	}
	value, err := loadSlot(args[0])
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errNoSession) {
		if _, statErr := os.Stat(secretPath(args[0])); dir != "" && statErr == nil {
			return fmt.Errorf("%s is sealed: run picoseal unseal", args[0])
		}
		return fmt.Errorf("%s: no such secret", args[0])
	}
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(value)
	return err
}

func cmdList(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	loaded, err := slots()
	if err != nil {
		return err
	}
	names := map[string]string{}
	for name := range loaded {
		names[name] = name
	}
	if dir != "" {
		entries, err := os.ReadDir(filepath.Join(dir, "secrets"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, entry := range entries {
			if _, ok := names[entry.Name()]; !ok {
				names[entry.Name()] = entry.Name() + " sealed"
			}
		}
	}
	lines := make([]string, 0, len(names))
	for _, line := range names {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	for _, line := range lines {
		if _, err := fmt.Println(line); err != nil {
			return err
		}
	}
	return nil
}

func cmdRemove(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	name := args[0]
	if err := checkName(name); err != nil {
		return err
	}
	found := false
	if id, _, err := findSlot(name); err == nil || errors.Is(err, errDamaged) {
		if err := removeSegment(id); err != nil {
			return err
		}
		found = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if dir != "" {
		err := os.Remove(secretPath(name))
		if err == nil {
			found = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if !found {
		return fmt.Errorf("%s: no such secret", name)
	}
	return nil
}

func cmdPubkey(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	pub, _, err := sessionKey(true)
	if err != nil {
		return err
	}
	_, err = io.WriteString(os.Stdout, encodeKey(pub))
	return err
}

func cmdExport(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	pub, ok := parseKey(args[0])
	if !ok {
		return errors.New("not a picoseal public key")
	}
	value, err := readSecret("Secret")
	if err != nil {
		return err
	}
	record, err := seal(pub, value)
	if err != nil {
		return err
	}
	_, err = io.WriteString(os.Stdout, record)
	return err
}

func cmdImport(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxRecord+1))
	if err != nil {
		return err
	}
	if len(data) > maxRecord {
		return errors.New("stdin: not a picoseal record")
	}
	pub, priv, err := sessionKey(false)
	if err != nil {
		return err
	}
	value, err := openRecord(data, "stdin", pub, priv)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(value)
	return err
}

func isTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// readSecret takes a value off a pipe as it is, and off a terminal without
// echoing it.
func readSecret(prompt string) ([]byte, error) {
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
		return nonEmpty(prompt, strings.TrimSuffix(string(piped), "\n"))
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

	fmt.Fprint(os.Stderr, prompt+": ")
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, maxTerminal+1)).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && err != io.EOF {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) >= maxTerminal {
		return nil, fmt.Errorf("a terminal line of %d bytes or more may be cut; pipe it instead", maxTerminal)
	}
	return nonEmpty(prompt, line)
}

func nonEmpty(prompt, value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty " + strings.ToLower(prompt))
	}
	return []byte(value), nil
}
