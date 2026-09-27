package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/unix"
)

// A request is one line "<command> <user 0|1> <name or ->" and the payload
// up to the end of the stream; the answer is "ok" or "error <message>" on the
// first line and the payload after it. A client gets a few seconds to send
// its request, and each uid but root only so many at once, so a stuck or
// hostile client cannot hold the service for anyone else. Each space answers
// one request at a time; the space table and the Argon2 child are the only
// things spaces share.
// Stored values rest in locked pages; a request, its answer and the Argon2
// child hold working copies in ordinary memory, cleared once they are done.

const (
	maxClients    = 256
	maxUIDClients = 8
	timeout       = 10 * time.Second
	// userPages caps the locked pages of one user's space, and when the
	// service's memlock limit binds, all users together get at most half of
	// it, so root always has room.
	userPages = 256
)

var errNoSession = errors.New("no session key since the service started: take a fresh pubkey")

type space struct {
	mu      sync.Mutex
	pub     *[32]byte
	priv    *locked
	secrets map[string]*locked
	pages   int
	users   *budget // nil for root's space
}

// budget counts the locked pages of all users' spaces.
type budget struct {
	mu         sync.Mutex
	used, most int
}

func (b *budget) take(pages int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+pages > b.most {
		return false
	}
	b.used += pages
	return true
}

func (b *budget) give(pages int) {
	b.mu.Lock()
	b.used -= pages
	b.mu.Unlock()
}

func usersBudget() *budget {
	var limit unix.Rlimit
	caps := [2]unix.CapUserData{}
	unix.Capget(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &caps[0])
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil || limit.Cur == unix.RLIM_INFINITY || caps[0].Effective&(1<<unix.CAP_IPC_LOCK) != 0 {
		return &budget{most: 1 << 30}
	}
	return &budget{most: int(limit.Cur) / os.Getpagesize() / 2}
}

// locked holds a value in its own anonymous pages, locked against swap and
// left out of core dumps.
type locked struct {
	pages []byte
	n     int
}

func (sp *space) lock(value []byte) (*locked, error) {
	pageSize := os.Getpagesize()
	size := max((len(value)+pageSize-1)/pageSize, 1) * pageSize
	if sp.users != nil && (sp.pages+size/pageSize > userPages || !sp.users.take(size/pageSize)) {
		return nil, errors.New("this space holds as much as it may")
	}
	pages, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err == nil {
		if err = unix.Mlock(pages); err != nil {
			unix.Munmap(pages)
			err = fmt.Errorf("lock a secret in memory: %w", err)
		}
	}
	if err != nil {
		if sp.users != nil {
			sp.users.give(size / pageSize)
		}
		return nil, err
	}
	unix.Madvise(pages, unix.MADV_DONTDUMP)
	copy(pages, value)
	sp.pages += size / pageSize
	return &locked{pages, len(value)}, nil
}

func (l *locked) value() []byte { return l.pages[:l.n] }

func (sp *space) free(l *locked) {
	clear(l.pages)
	pages := len(l.pages) / os.Getpagesize()
	sp.pages -= pages
	if sp.users != nil {
		sp.users.give(pages)
	}
	unix.Munmap(l.pages)
}

type server struct {
	mu     sync.Mutex
	spaces map[int]*space
	active map[int]int
	users  *budget
	derive sync.Mutex
}

func newServer() *server {
	return &server{spaces: map[int]*space{}, active: map[int]int{}, users: usersBudget()}
}

// store is a space's directory: key salts the password, unseal holds the
// public U, secrets/ holds a cryptobox for U per name. The service trusts it
// only as a root-owned directory nobody else may write, and follows no
// symbolic link inside it.
type store struct{ dir string }

func (st store) keyPath() string    { return filepath.Join(st.dir, "key") }
func (st store) unsealPath() string { return filepath.Join(st.dir, "unseal") }
func (st store) secretsDir() string { return filepath.Join(st.dir, "secrets") }
func (st store) secretPath(name string) string {
	return filepath.Join(st.secretsDir(), name)
}

// check refuses a store if any directory from /etc/picoseal down to its
// secrets is a link, not root's, or writable by others; a missing directory
// is fine, it holds nothing yet.
func (st store) check() error {
	chain := []string{base}
	if st.dir != base {
		chain = append(chain, filepath.Dir(st.dir), st.dir)
	}
	for _, dir := range append(chain, st.secretsDir()) {
		var info unix.Stat_t
		if err := unix.Lstat(dir, &info); errors.Is(err, unix.ENOENT) {
			return nil
		} else if err != nil {
			return err
		}
		if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != uint32(os.Geteuid()) || info.Mode&0o022 != 0 {
			return fmt.Errorf("%s is not a store directory", dir)
		}
	}
	return nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 2*maxBox))
}

// unsealKey returns the public U of a store unsealed once, or nil.
func (st store) unsealKey() (*[32]byte, error) {
	data, err := readFile(st.unsealPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	key, ok := parseKey(string(data))
	if !ok {
		return nil, fmt.Errorf("%s: not a picoseal key", st.unsealPath())
	}
	return key, nil
}

func (st store) ensureKey() error {
	if err := st.check(); err != nil {
		return err
	}
	for _, dir := range []string{st.dir, st.secretsDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if err := st.check(); err != nil {
		return err
	}
	_, secret, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err = writeNew(st.keyPath(), encodeKey(secret)); errors.Is(err, os.ErrExist) {
		return nil
	}
	return err
}

func cmdServe(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	if err := asRoot(); err != nil {
		return err
	}
	if conn, err := net.Dial("unix", sockPath); err == nil {
		conn.Close()
		return errors.New("picoseal serve is already running")
	}
	os.Remove(sockPath)
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(sockPath, 0o666); err != nil {
		return err
	}
	s := newServer()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, unix.SIGTERM, os.Interrupt)
	go func() {
		<-stop
		os.Remove(sockPath)
		s.mu.Lock()
		for _, sp := range s.spaces {
			sp.mu.Lock()
			sp.seal()
			if sp.priv != nil {
				sp.free(sp.priv)
			}
		}
		os.Exit(0)
	}()
	return s.listen(listener)
}

func (s *server) listen(listener net.Listener) error {
	slots := make(chan struct{}, maxClients)
	for {
		slots <- struct{}{}
		conn, err := listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		if err != nil {
			<-slots
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go func() {
			defer func() { <-slots }()
			s.handle(conn.(*net.UnixConn))
		}()
	}
}

func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	if err := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if err != nil {
		return -1, err
	}
	return int(cred.Uid), nil
}

func (s *server) handle(conn *net.UnixConn) {
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil {
		return
	}
	s.mu.Lock()
	busy := uid != 0 && s.active[uid] >= maxUIDClients
	if !busy {
		s.active[uid]++
	}
	s.mu.Unlock()
	if busy {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		io.Copy(io.Discard, io.LimitReader(conn, 2*maxBox+256))
		io.WriteString(conn, "error too many requests at once\n")
		return
	}
	defer func() {
		s.mu.Lock()
		s.active[uid]--
		s.mu.Unlock()
	}()
	conn.SetReadDeadline(time.Now().Add(timeout))
	reply, err := s.answer(conn, uid)
	defer clear(reply)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		fmt.Fprintf(conn, "error %s\n", strings.ReplaceAll(err.Error(), "\n", "; "))
		return
	}
	if _, err := io.WriteString(conn, "ok\n"); err == nil {
		conn.Write(reply)
	}
}

// payloadLimit is the most each command takes after its header.
var payloadLimit = map[string]int{
	"add":    maxValue,
	"unseal": maxValue,
	"import": 2 * maxBox,
}

func (s *server) answer(conn *net.UnixConn, uid int) ([]byte, error) {
	header := make([]byte, 0, 128)
	for one := make([]byte, 1); len(header) < cap(header); {
		if _, err := io.ReadFull(conn, one); err != nil {
			return nil, errors.New("malformed request")
		}
		if one[0] == '\n' {
			break
		}
		header = append(header, one[0])
	}
	fields := strings.Fields(string(header))
	if len(fields) != 3 || (fields[1] != "0" && fields[1] != "1") {
		return nil, errors.New("malformed request")
	}
	payload := make([]byte, payloadLimit[fields[0]]+1)
	defer clear(payload)
	n, err := io.ReadFull(conn, payload)
	if n == len(payload) {
		return nil, errors.New("request too large")
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return s.do(uid, fields[1] == "1", fields[0], fields[2], payload[:n])
}

// do runs a command in the space the uid and --user select.
func (s *server) do(uid int, user bool, command, name string, payload []byte) ([]byte, error) {
	switch {
	case user && uid == 0:
		return nil, errors.New("--user is for a user other than root")
	case !user && uid != 0:
		return nil, errRoot
	}
	st := store{base}
	if user {
		st = store{filepath.Join(base, "users", strconv.Itoa(uid))}
	}
	if err := st.check(); err != nil {
		return nil, err
	}
	switch command {
	case "add", "open", "remove":
		if err := checkName(name); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	sp := s.spaces[uid]
	if sp == nil {
		sp = &space{secrets: map[string]*locked{}}
		if uid != 0 {
			sp.users = s.users
		}
		s.spaces[uid] = sp
	}
	s.mu.Unlock()
	sp.mu.Lock()
	defer sp.mu.Unlock()
	switch command {
	case "pubkey":
		if sp.priv == nil {
			pub, priv, err := box.GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			defer clear(priv[:])
			if sp.priv, err = sp.lock(priv[:]); err != nil {
				return nil, err
			}
			sp.pub = pub
		}
		return []byte(encodeKey(sp.pub)), nil
	case "import":
		if sp.priv == nil {
			return nil, errNoSession
		}
		return openBox(payload, "stdin", sp.pub, (*[32]byte)(sp.priv.value()))
	case "add":
		return nil, sp.add(st, name, payload)
	case "open":
		if value, ok := sp.secrets[name]; ok {
			return bytes.Clone(value.value()), nil
		}
		if _, err := os.Lstat(st.secretPath(name)); err == nil {
			return nil, fmt.Errorf("%s is sealed: run picoseal unseal", name)
		}
		return nil, fmt.Errorf("%s: no such secret", name)
	case "list":
		return sp.list(st)
	case "remove":
		return nil, sp.remove(st, name)
	case "seal":
		sp.seal()
		return nil, nil
	case "unseal":
		return nil, sp.unseal(st, payload, name == "confirmed", &s.derive)
	}
	return nil, fmt.Errorf("unknown command %q", command)
}

func (sp *space) add(st store, name string, value []byte) error {
	if len(value) == 0 {
		return errors.New("empty secret")
	}
	if _, ok := sp.secrets[name]; ok {
		return fmt.Errorf("%s already exists", name)
	}
	if _, err := os.Lstat(st.secretPath(name)); err == nil {
		return fmt.Errorf("%s already exists", name)
	}
	unsealPub, err := st.unsealKey()
	if err != nil {
		return err
	}
	held, err := sp.lock(value)
	if err != nil {
		return err
	}
	if unsealPub != nil {
		cryptobox, err := makeBox(unsealPub, value)
		if err == nil {
			err = writeNew(st.secretPath(name), cryptobox)
		}
		if err != nil {
			sp.free(held)
			return fmt.Errorf("%s not stored: %w", name, err)
		}
	}
	sp.secrets[name] = held
	return nil
}

func (sp *space) list(st store) ([]byte, error) {
	lines := []string{}
	for name := range sp.secrets {
		lines = append(lines, name)
	}
	entries, err := os.ReadDir(st.secretsDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, entry := range entries {
		if _, ok := sp.secrets[entry.Name()]; !ok {
			lines = append(lines, entry.Name()+" sealed")
		}
	}
	sort.Strings(lines)
	var out bytes.Buffer
	for _, line := range lines {
		out.WriteString(line + "\n")
	}
	return out.Bytes(), nil
}

func (sp *space) remove(st store, name string) error {
	value, found := sp.secrets[name]
	if found {
		sp.free(value)
		delete(sp.secrets, name)
	}
	err := os.Remove(st.secretPath(name))
	if err == nil {
		found = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !found {
		return fmt.Errorf("%s: no such secret", name)
	}
	return nil
}

func (sp *space) seal() {
	for name, value := range sp.secrets {
		sp.free(value)
		delete(sp.secrets, name)
	}
}

// unseal checks the password against the store's public U, or sets it on a
// confirmed first unseal, loads every cryptobox on disk that is not in memory
// yet and stores on disk every secret that is only in memory.
func (sp *space) unseal(st store, password []byte, confirmed bool, derive *sync.Mutex) error {
	if len(password) == 0 {
		return errors.New("empty password")
	}
	unsealPub, err := st.unsealKey()
	if err != nil {
		return err
	}
	if unsealPub == nil && !confirmed {
		return errConfirm
	}
	if err := st.ensureKey(); err != nil {
		return err
	}
	data, err := readFile(st.keyPath())
	if err != nil {
		return err
	}
	key, ok := parseKey(string(data))
	if !ok {
		return fmt.Errorf("%s: not a picoseal key", st.keyPath())
	}
	derive.Lock()
	pub, priv, err := deriveU(key, password)
	derive.Unlock()
	if err != nil {
		return err
	}
	defer clear(priv[:])
	if unsealPub == nil {
		if err := writeNew(st.unsealPath(), encodeKey(pub)); err != nil {
			return err
		}
	} else if *pub != *unsealPub {
		return errors.New("wrong password")
	}
	entries, err := os.ReadDir(st.secretsDir())
	if err != nil {
		return err
	}
	var failed []error
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := sp.secrets[name]; ok {
			continue
		}
		data, err := readFile(st.secretPath(name))
		if err == nil {
			var value []byte
			if value, err = openBox(data, st.secretPath(name), pub, priv); err == nil {
				var held *locked
				if held, err = sp.lock(value); err == nil {
					sp.secrets[name] = held
				}
				clear(value)
			}
		}
		if err != nil {
			failed = append(failed, err)
		}
	}
	for name, value := range sp.secrets {
		if _, err := os.Lstat(st.secretPath(name)); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		cryptobox, err := makeBox(pub, value.value())
		if err == nil {
			err = writeNew(st.secretPath(name), cryptobox)
		}
		if err != nil {
			failed = append(failed, fmt.Errorf("%s not stored: %w", name, err))
		}
	}
	return errors.Join(failed...)
}

// deriveU runs Argon2id in a child of the service's own binary, outside the
// service's memory.
var deriveU = func(key *[32]byte, password []byte) (pub, priv *[32]byte, err error) {
	child := exec.Command("/proc/self/exe", "derive", strconv.Itoa(int(argonMemory)))
	input := append(saltFor(key), password...)
	defer clear(input)
	child.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	child.Stderr = &stderr
	out, err := child.Output()
	defer clear(out)
	if err != nil || len(out) != 32 {
		reason := strings.TrimSpace(strings.TrimPrefix(stderr.String(), "picoseal: "))
		if reason == "" && err != nil {
			reason = err.Error()
		}
		return nil, nil, fmt.Errorf("derive: %s", reason)
	}
	priv = new([32]byte)
	copy(priv[:], out)
	return publicKey(priv), priv, nil
}

func saltFor(key *[32]byte) []byte {
	salt := sha256.Sum256(append([]byte("picoseal unseal\x00"), key[:]...))
	return salt[:]
}

// cmdDerive reads a 32-byte salt and a password and prints U.
func cmdDerive(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	kib, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return errUsage
	}
	if limit, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		if max, err := strconv.ParseUint(strings.TrimSpace(string(limit)), 10, 64); err == nil && max < kib<<10+64<<20 {
			return fmt.Errorf("unseal needs %d MiB of memory, the cgroup allows %d MiB", kib>>10+64, max>>20)
		}
	}
	in, err := io.ReadAll(io.LimitReader(os.Stdin, 32+maxValue))
	if err != nil || len(in) <= 32 {
		return errUsage
	}
	_, err = os.Stdout.Write(argon2.IDKey(in[32:], in[:32], 3, uint32(kib), 1, 32))
	return err
}

func publicKey(priv *[32]byte) *[32]byte {
	var pub [32]byte
	derived, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], derived)
	return &pub
}
