// picoseal keeps secrets for scripts in the memory of one service. picoseal
// serve runs as root, out of reach of dumps and tracing, and holds for each
// space a session key E and the secrets in pages locked against swap. The
// space follows the uid the kernel reports for the socket peer: root's for uid
// 0, and with --user the caller's own; every other command is a client of that
// socket, except export, which puts stdin in a cryptobox for a public key
// alone.
// A space whose store init has set up also keeps every secret add keeps on
// disk as a cryptobox for U, which Argon2id derives from a password and a
// random salt; the service forgets U once the store is loaded.
// Stores live under /etc/picoseal, root's at the top and each user's in
// users/<uid>, and the service takes the path from the uid, never from a
// request. Permissions are the whole boundary: only root reaches root's
// secrets, and scripts an administrator has pinned are the only way an
// unprivileged caller reaches one. Never pin picoseal with free arguments.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
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
	maxBox      = (maxValue+box.AnonymousOverhead+2)/3*4 + 1
	binPath     = "/usr/local/bin/picoseal"
)

var (
	base     = "/etc/picoseal"
	sockPath = "/run/picoseal.sock"
	asUser   bool
	nameRe   = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	errUsage = errors.New("usage")
	errRoot  = errors.New("this runs as root: use sudo")
)

func main() {
	unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	args := os.Args[1:]
	flags := 0
	for flags < len(args) && strings.HasPrefix(args[flags], "--") {
		flags++
	}
	if flags == len(args) {
		usage()
		os.Exit(1)
	}
	var err error
	if local, ok := map[string]func([]string) error{
		"install": cmdInstall,
		"serve":   cmdServe,
		"export":  cmdExport,
	}[args[flags]]; ok {
		for _, flag := range args[:flags] {
			if flag != "--user" {
				usage()
				os.Exit(1)
			}
			asUser = true
		}
		err = local(args[flags+1:])
	} else {
		err = remote(args, args[flags])
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
	fmt.Fprintf(os.Stderr, `picoseal — secrets in locked memory for root scripts

One service, picoseal serve, keeps every secret in its locked memory until it
stops or seal. add also keeps them in a store with a password, and unseal
reloads them from it.

  install          Copy the binary to %s
  serve            Run the service that holds the secrets
  init             Set the store password, asked twice on a terminal
  unseal           Ask the store password and load the secrets on disk into
                   memory
  seal             Drop every secret from memory
  add <name>       Keep stdin as <name> in memory and in the store init set up:
                   one unechoed line from a terminal, under %d bytes, or
                   a whole pipe, up to %d bytes counting the one trailing
                   newline it strips
  adde <name>      Keep stdin, read the same way, as <name> in memory only
  open <name>      Print the secret
  list             List names; "sealed" marks those on disk only, "memory"
                   those in memory only
  remove <name>    Delete a secret from memory and disk
  pubkey           Print the session public key
  export <pubkey>  Put stdin, read the same way, in a cryptobox for the session
                   with <pubkey> and print it
  import           Open the cryptobox on stdin, as export prints it, read the
                   same way, and print the secret

  --user           Use the caller's own space instead of root's

Every command but export works as root, or with --user as the caller. Only root
reaches root's secrets.
`, binPath, maxTerminal, maxValue)
}

func checkName(name string) error {
	if !nameRe.MatchString(name) || name == "." || name == ".." {
		return errors.New("name must match [a-z0-9._-]{1,64}")
	}
	return nil
}

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

func makeBox(pub *[32]byte, value []byte) (string, error) {
	raw, err := box.SealAnonymous(nil, value, pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw) + "\n", nil
}

func openBox(data []byte, source string, pub, priv *[32]byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) <= box.AnonymousOverhead {
		return nil, fmt.Errorf("%s: not a picoseal cryptobox", source)
	}
	value, ok := box.OpenAnonymous(nil, raw, pub, priv)
	if !ok {
		return nil, fmt.Errorf("%s: not a cryptobox for this key", source)
	}
	return value, nil
}

func asRoot() error {
	if asUser {
		return errors.New("--user is for a user other than root")
	}
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
		return fmt.Errorf("%s not installed: %w", binPath, err)
	}
	if err := os.Chmod(staged, mode); err != nil {
		return err
	}
	if err := os.Rename(staged, binPath); err != nil {
		return err
	}
	fmt.Printf("installed %s\n", binPath)
	return nil
}

// reads says what a command takes from stdin before it asks the service.
var reads = map[string]struct {
	prompt string
	limit  int
}{
	"add":    {"Secret", maxValue},
	"adde":   {"Secret", maxValue},
	"import": {"Cryptobox", 2 * maxBox},
	"init":   {"Password", maxValue},
	"unseal": {"Password", maxValue},
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
	if command == "init" && isTerminal() {
		again, err := readSecret("Password again", maxValue)
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
	_, err = os.Stdout.Write(body)
	return err
}

// request sends the number of arguments and each argument, every one ended
// by a zero byte, then the payload, and returns the service's answer.
func request(args []string, payload []byte) ([]byte, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, errors.New("picoseal serve is not running")
	}
	defer conn.Close()
	header := fmt.Sprintf("%d\x00", len(args))
	for _, arg := range args {
		header += arg + "\x00"
	}
	if _, err := io.WriteString(conn, header); err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	conn.(*net.UnixConn).CloseWrite()
	reply, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}
	status, body, _ := bytes.Cut(reply, []byte("\n"))
	if string(status) != "ok" {
		return nil, errors.New(strings.TrimPrefix(string(status), "error "))
	}
	return body, nil
}

func cmdExport(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	pub, ok := parseKey(args[0])
	if !ok {
		return errors.New("not a picoseal public key")
	}
	value, err := readSecret("Secret", maxValue)
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

func isTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
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
			return nil, fmt.Errorf("%s exceeds %d bytes", strings.ToLower(prompt), limit)
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
