// picoseal keeps secrets for scripts in the memory of one service. picoseal
// serve runs as root, out of reach of dumps and tracing, and holds for each
// space a session key E and the secrets in pages locked against swap. The space
// follows the uid the kernel reports for the socket peer: root's for uid 0, and
// with --user the caller's own; pubkey gives anyone root's. Every command but
// install, serve, export and version is a client of that socket, and export
// puts stdin in a cryptobox for a public key alone.
// Root's space alone may have a store, /etc/picoseal, set up by init: save
// keeps a secret there too, as a cryptobox for U, which Argon2id derives from a
// password and a random salt; the service forgets U once the store is loaded. A
// user's space lives in memory only. Permissions are the whole boundary: only
// root reaches root's secrets, and scripts an administrator has pinned are the
// only way an unprivileged caller reaches one. Never pin picoseal with free
// arguments.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/unix"
)

const (
	// maxValue caps a piped secret; a terminal line is capped by the canonical
	// buffer of the tty driver, which discards the rest without telling anyone.
	maxValue    = 64 << 10
	maxTerminal = 4095
	// block pads what a cryptobox holds, so its size tells the secret's
	// length only to within block bytes.
	block   = 64
	maxBox  = (((maxValue/block+1)*block+box.AnonymousOverhead)*8+4)/5 + 1
	binPath = "/usr/local/bin/picoseal"
)

// text writes keys and cryptoboxes in lowercase unpadded base32: letters and
// digits only, so a double click selects one whole.
var text = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// version is the release tag, set when a release is built.
var version = "dev"

var (
	base        = "/etc/picoseal"
	sockPath    = "/run/picoseal.sock"
	nameRe      = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	errUsage    = errors.New("usage")
	errRoot     = errors.New("needs root")
	errRootUser = errors.New("root has no --user")
	errOther    = errors.New("cryptobox for another key")
	errUnknown  = errors.New("unknown command")
)

func main() {
	unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	args := os.Args[1:]
	at := 0
	if len(args) > 0 && args[0] == "--user" {
		at = 1
	}
	if at == len(args) || strings.HasPrefix(args[at], "-") {
		usage()
		os.Exit(1)
	}
	var err error
	if local, ok := map[string]func([]string) error{
		"install": cmdInstall,
		"serve":   cmdServe,
		"export":  cmdExport,
		"version": cmdVersion,
	}[args[at]]; ok && at == 0 {
		err = local(args[1:])
	} else if ok {
		err = errUsage
	} else {
		err = remote(args, args[at])
	}
	if err != nil && err.Error() == errUnknown.Error() {
		fmt.Fprintf(os.Stderr, "picoseal: unknown command %q\n\n", args[at])
		err = errUsage
	}
	if err != nil && err.Error() == errUsage.Error() {
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "picoseal: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `picoseal %s — secrets in locked memory for root scripts

One service, picoseal serve, keeps every secret in its locked memory until it
stops. save also keeps them in a store with a password: seal drops those from
memory, and unseal reloads them.

  install          Copy the binary to %s
  serve            Run the service that holds the secrets
  init             Set the store password, asked twice on a terminal
  unseal           Ask the store password and load the secrets on disk into
                   memory
  seal             Drop from memory the secrets the store keeps
  add <name>       Keep stdin as <name> in memory only: one unechoed line from
                   a terminal, under %d bytes, or a whole pipe, up to %d
                   bytes counting the one trailing newline it strips
  save <name>      Keep stdin, read the same way, as <name> in memory and in
                   the store init set up
  open <name>      Print the secret
  list             List names, + for those open and - for those waiting for
                   unseal, with their state: unsealed, sealed, or memory for
                   those add keeps
  remove <name>    Delete a secret from memory and disk
  pubkey           Print the session public key, root's to anyone
  export <pubkey>  Put stdin, read the same way, in a cryptobox for the session
                   with <pubkey> and print it
  import           Open the cryptobox on stdin, as export prints it, read the
                   same way, and print the secret

  version          Print the version

  --user           Use the caller's own space, in memory only, instead of
                   root's

Every command but export, version and pubkey needs root; --user takes the
caller's own space instead, in memory only. Only root reaches root's secrets.
`, version, binPath, maxTerminal, maxValue)
}

func checkName(name string) error {
	if !nameRe.MatchString(name) || name == "." || name == ".." {
		return fmt.Errorf("name must match [a-z0-9._-]{1,64}, not %q", name)
	}
	return nil
}

func parseKey(s string) (*[32]byte, bool) {
	raw, err := text.DecodeString(strings.ToLower(strings.TrimSpace(s)))
	if err != nil || len(raw) != 32 {
		return nil, false
	}
	var key [32]byte
	copy(key[:], raw)
	return &key, true
}

func encodeKey(key *[32]byte) string {
	return text.EncodeToString(key[:]) + "\n"
}

// makeBox pads value with 0x80 and zeros to a whole block and seals it.
func makeBox(pub *[32]byte, value []byte) (string, error) {
	padded := make([]byte, (len(value)/block+1)*block)
	defer clear(padded)
	copy(padded, value)
	padded[len(value)] = 0x80
	raw, err := box.SealAnonymous(nil, padded, pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return text.EncodeToString(raw) + "\n", nil
}

func openBox(data []byte, pub, priv *[32]byte) ([]byte, error) {
	raw, err := text.DecodeString(strings.ToLower(strings.TrimSpace(string(data))))
	if err != nil || len(raw) <= box.AnonymousOverhead {
		return nil, errors.New("not a cryptobox")
	}
	value, ok := box.OpenAnonymous(nil, raw, pub, priv)
	if !ok {
		return nil, errOther
	}
	end := len(value) - 1
	for end >= 0 && value[end] == 0 {
		end--
	}
	if end < 0 || value[end] != 0x80 || len(value)%block != 0 {
		clear(value)
		return nil, errors.New("not a cryptobox")
	}
	return value[:end], nil
}

func asRoot() error {
	if os.Geteuid() != 0 {
		return errRoot
	}
	return nil
}

func cmdInstall(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	if err := asRoot(); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil || self == binPath {
		return err
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o755)
	if installed, err := os.Stat(binPath); err == nil {
		mode = installed.Mode().Perm()
	}
	staged := binPath + ".new"
	if err := os.WriteFile(staged, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(staged, mode); err != nil {
		return err
	}
	if err := os.Rename(staged, binPath); err != nil {
		return err
	}
	return nil
}

// reads says what a command takes from stdin before it asks the service.
var reads = map[string]struct {
	prompt string
	limit  int
}{
	"add":    {"secret", maxValue},
	"save":   {"secret", maxValue},
	"import": {"cryptobox", 2 * maxBox},
	"init":   {"password", maxValue},
	"unseal": {"password", maxValue},
}

// remote checks the arguments with the service's own parser before it reads
// stdin, sends them to the service and prints its answer.
func remote(args []string, command string) error {
	if _, _, _, err := parse(args); err != nil {
		return err
	}
	var payload []byte
	if in, ok := reads[command]; ok {
		var err error
		if payload, err = readSecret(in.prompt, in.limit); err != nil {
			return err
		}
	}
	if command == "init" && isTerminal(os.Stdin) {
		again, err := readSecret("password again", maxValue)
		if err != nil {
			return err
		}
		if !bytes.Equal(again, payload) {
			return errors.New("passwords differ")
		}
	}
	body, err := request(args, payload)
	if err != nil {
		return err
	}
	if _, err = os.Stdout.Write(body); err == nil && (command == "open" || command == "import") && isTerminal(os.Stdout) {
		_, err = fmt.Println()
	}
	return err
}

// request sends the number of arguments and each argument, every one ended
// by a zero byte, then the payload, and returns the service's answer.
func request(args []string, payload []byte) ([]byte, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, errors.New("the service is not running")
	}
	defer conn.Close()
	header := fmt.Sprintf("%d\x00", len(args))
	for _, arg := range args {
		header += arg + "\x00"
	}
	_, sent := io.WriteString(conn, header)
	if sent == nil {
		_, sent = conn.Write(payload)
	}
	conn.(*net.UnixConn).CloseWrite()
	reply, err := io.ReadAll(conn)
	if len(reply) == 0 && sent != nil {
		return nil, sent
	}
	if err != nil {
		return nil, err
	}
	if len(reply) == 0 {
		return nil, errors.New("the service stopped before it answered")
	}
	status, body, _ := bytes.Cut(reply, []byte("\n"))
	if string(status) != "ok" {
		return nil, errors.New(strings.TrimPrefix(string(status), "error "))
	}
	return body, nil
}

func cmdVersion(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	fmt.Println(version)
	return nil
}

func cmdExport(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	pub, ok := parseKey(args[0])
	if !ok {
		return fmt.Errorf("not a pubkey %q", args[0])
	}
	value, err := readSecret("secret", maxValue)
	if err != nil {
		return err
	}
	cryptobox, err := makeBox(pub, value)
	if err != nil {
		return err
	}
	_, err = io.WriteString(os.Stdout, cryptobox)
	return err
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// writeNew publishes data at path whole and synced, or fails and leaves path
// as it was; a crash can leave only a Tmp file, a name no secret can take.
func writeNew(path, data string) error {
	f, err := os.CreateTemp(filepath.Dir(path), "Tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = io.WriteString(f, data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Link(f.Name(), path)
	}
	if err != nil {
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

// readSecret takes a value off a pipe as it is, and off a terminal without
// echoing it.
func readSecret(prompt string, limit int) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		piped, err := io.ReadAll(io.LimitReader(os.Stdin, int64(limit)+1))
		if err != nil {
			return nil, err
		}
		if len(piped) > limit {
			return nil, fmt.Errorf("%s exceeds %d bytes", prompt, limit)
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

	fmt.Fprintf(os.Stderr, "picoseal input (%s): ", prompt)
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, maxTerminal+1)).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && err != io.EOF {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) >= maxTerminal {
		return nil, fmt.Errorf("terminal line exceeds %d bytes", maxTerminal-1)
	}
	return nonEmpty(prompt, line)
}

func nonEmpty(prompt, value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty " + prompt)
	}
	return []byte(value), nil
}
