package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
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

// A request is the number of the client's arguments and the arguments, each
// ended by a zero byte, then the payload up to the end of the stream. parse
// is the one parser of those arguments: the client runs it before it reads
// stdin, and the service runs it again on what arrives. The answer is "ok" or
// "error <message>" on the first line and the payload after it. A client gets
// a few seconds to send its request. Each uid but root holds only so many
// connections, and the rest are turned away at once; root is never turned
// away. Requests are read side by side but run one at a time under the
// server's one lock, Argon2 included: everything a request does runs as in a
// single thread, and nothing else in the service locks. Stored values rest in
// locked pages; a request, its answer and Argon2 hold working copies in
// ordinary memory, cleared or given back to the system once they are done.

const (
	maxClients    = 256
	argonMemory   = 1 << 20 // KiB
	maxUIDClients = 8
	timeout       = 10 * time.Second
	// userPages caps the locked pages of one user's space, and when the service's
	// memlock limit binds, all users together get at most half of it, so root
	// always has room.
	userPages = 256
)

var errNoSession = errors.New("no session key")

type space struct {
	pub     *[32]byte
	priv    *locked
	secrets map[string]*locked
	pages   int
	users   *budget // nil for root's space
}

// budget counts the locked pages of all users' spaces.
type budget struct{ used, most int }

func (b *budget) take(pages int) bool {
	if b.used+pages > b.most {
		return false
	}
	b.used += pages
	return true
}

func (b *budget) give(pages int) { b.used -= pages }

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
		return nil, errors.New("the space is full")
	}
	pages, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err == nil {
		if err = unix.Mlock(pages); err != nil {
			unix.Munmap(pages)
			err = fmt.Errorf("cannot lock the secret in memory (%w)", err)
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
	return &locked{pages: pages, n: len(value)}, nil
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
	root   int // the uid whose space is root's
	mu     sync.Mutex
	spaces map[int]*space
	users  *budget
}

func newServer(root int) *server {
	return &server{root: root, spaces: map[int]*space{}, users: usersBudget()}
}

// store is root's directory: unseal holds the password's salt and the
// public U, secrets/ holds a cryptobox for U per name. The service trusts it
// only as a root-owned directory nobody else may write, and follows no
// symbolic link inside it.
type store struct{ dir string }

func (st store) unsealPath() string { return filepath.Join(st.dir, "unseal") }
func (st store) secretsDir() string { return filepath.Join(st.dir, "secrets") }
func (st store) secretPath(name string) string {
	return filepath.Join(st.secretsDir(), name)
}

// check refuses the store if it or its secrets directory is a link, not
// root's, or writable by others; a missing directory is fine, it holds nothing
// yet.
func (st store) check() error {
	for _, dir := range []string{st.dir, st.secretsDir()} {
		var info unix.Stat_t
		if err := unix.Lstat(dir, &info); errors.Is(err, unix.ENOENT) {
			return nil
		} else if err != nil {
			return err
		}
		if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != uint32(os.Geteuid()) || info.Mode&0o022 != 0 {
			return fmt.Errorf("not a store directory %q", dir)
		}
	}
	return nil
}

// holds reports whether the store keeps name on disk; a user's space has no
// store.
func (st *store) holds(name string) bool {
	if st == nil {
		return false
	}
	_, err := os.Lstat(st.secretPath(name))
	return err == nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 2*maxBox))
}

// unsealKey returns the salt and the public U of a store init has set up, or
// nils.
func (st store) unsealKey() (salt, pub *[32]byte, err error) {
	data, err := readFile(st.unsealPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	fields := strings.Fields(string(data))
	ok := len(fields) == 2
	if ok {
		salt, ok = parseKey(fields[0])
	}
	if ok {
		pub, ok = parseKey(fields[1])
	}
	if !ok {
		return nil, nil, fmt.Errorf("not an unseal file %q", st.unsealPath())
	}
	return salt, pub, nil
}

func (st store) makeDirs() error {
	if err := st.check(); err != nil {
		return err
	}
	for _, dir := range []string{st.dir, st.secretsDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return st.check()
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
		return errors.New("the service is already running")
	}
	os.Remove(sockPath)
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(sockPath, 0o666); err != nil {
		return err
	}
	s := newServer(rootUID)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, unix.SIGTERM, os.Interrupt)
	go func() {
		<-stop
		os.Remove(sockPath)
		s.mu.Lock()
		for _, sp := range s.spaces {
			for _, value := range sp.secrets {
				sp.free(value)
			}
			if sp.priv != nil {
				sp.free(sp.priv)
			}
		}
		os.Exit(0)
	}()
	return s.listen(listener)
}

// listen alone counts the connections of each uid but root, so turning one
// away never waits for a request that runs.
func (s *server) listen(listener net.Listener) error {
	active, total := map[int]int{}, 0
	done, refusing := make(chan int, maxClients), make(chan struct{}, maxClients)
	for {
		conn, err := listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		for len(done) > 0 {
			active[<-done]--
			total--
		}
		unixConn := conn.(*net.UnixConn)
		uid, err := peerUID(unixConn)
		counted := uid != s.root
		switch {
		case err != nil:
			conn.Close()
			continue
		case counted && (active[uid] >= maxUIDClients || total >= maxClients):
			select {
			case refusing <- struct{}{}:
				go func() {
					drain(unixConn)
					io.WriteString(conn, "error too many requests at once\n")
					conn.Close()
					<-refusing
				}()
			default:
				conn.Close()
			}
			continue
		case counted:
			active[uid]++
			total++
		}
		go func() {
			s.handle(unixConn, uid)
			if counted {
				done <- uid
			}
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

func (s *server) handle(conn *net.UnixConn, uid int) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	reply, err := s.answer(conn, uid)
	defer clear(reply)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		drain(conn)
		fmt.Fprintf(conn, "error %s\n", strings.ReplaceAll(err.Error(), "\n", "; "))
		return
	}
	if _, err := io.WriteString(conn, "ok\n"); err == nil {
		conn.Write(reply)
	}
}

// drain reads what is left of a refused request, so the client gets the
// answer rather than a reset connection.
func drain(conn *net.UnixConn) {
	conn.SetReadDeadline(time.Now().Add(time.Second))
	io.Copy(io.Discard, conn)
}

func (s *server) answer(conn *net.UnixConn, uid int) ([]byte, error) {
	field := func() (string, error) {
		var arg []byte
		for one := make([]byte, 1); ; {
			if _, err := io.ReadFull(conn, one); err != nil || len(arg) == 128 {
				return "", errors.New("malformed request")
			}
			if one[0] == 0 {
				return string(arg), nil
			}
			arg = append(arg, one[0])
		}
	}
	count, err := field()
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(count)
	if err != nil || n < 0 || n > 8 {
		return nil, errors.New("malformed request")
	}
	args := make([]string, n)
	for i := range args {
		if args[i], err = field(); err != nil {
			return nil, err
		}
	}
	user, command, name, err := parse(args)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, reads[command].limit+1)
	defer clear(payload)
	n, err = io.ReadFull(conn, payload)
	if n == len(payload) {
		return nil, errors.New("request too large")
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return s.do(uid, user, command, name, payload[:n])
}

// parse reads [--user] <command> [<name>] as the usage text lists them.
func parse(args []string) (user bool, command, name string, err error) {
	if len(args) > 0 && args[0] == "--user" {
		user, args = true, args[1:]
	}
	if len(args) == 0 {
		return false, "", "", errUsage
	}
	command, args = args[0], args[1:]
	if user && (command == "save" || command == "init" || command == "unseal" || command == "seal") {
		return false, "", "", errors.New("no store")
	}
	switch command {
	case "add", "save", "open", "remove":
		if len(args) != 1 {
			return false, "", "", errUsage
		}
		if err := checkName(args[0]); err != nil {
			return false, "", "", err
		}
		return user, command, args[0], nil
	case "list", "seal", "pubkey", "import", "init", "unseal":
		if len(args) == 0 {
			return user, command, "", nil
		}
	default:
		return false, "", "", errUnknown
	}
	return false, "", "", errUsage
}

// do runs a command in the space the uid and --user select.
func (s *server) do(uid int, user bool, command, name string, payload []byte) ([]byte, error) {
	switch {
	case user && uid == s.root:
		return nil, errRootUser
	case !user && uid != s.root && command != "pubkey":
		return nil, errRoot
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var st *store
	if !user {
		st = &store{base}
		if err := st.check(); err != nil {
			return nil, err
		}
	}
	owner := uid
	if !user {
		owner = s.root
	}
	sp := s.spaces[owner]
	if sp == nil {
		sp = &space{secrets: map[string]*locked{}}
		if owner != s.root {
			sp.users = s.users
		}
		s.spaces[owner] = sp
	}
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
		return openBox(payload, sp.pub, (*[32]byte)(sp.priv.value()))
	case "add", "save":
		return nil, sp.add(st, name, payload, command == "add")
	case "open":
		if value, ok := sp.secrets[name]; ok {
			return bytes.Clone(value.value()), nil
		}
		if st.holds(name) {
			return nil, fmt.Errorf("unseal is needed for %q", name)
		}
		return nil, fmt.Errorf("no such secret %q", name)
	case "list":
		return sp.list(st)
	case "remove":
		return nil, sp.remove(st, name)
	case "seal":
		sp.seal(st)
		return nil, nil
	case "init", "unseal":
		return nil, sp.unseal(st, payload, command == "init")
	}
	return nil, errUsage
}

func (sp *space) add(st *store, name string, value []byte, memoryOnly bool) error {
	if len(value) == 0 {
		return errors.New("empty secret")
	}
	if _, ok := sp.secrets[name]; ok || st.holds(name) {
		return fmt.Errorf("already exists %q", name)
	}
	var unsealPub *[32]byte
	if !memoryOnly {
		var err error
		if _, unsealPub, err = st.unsealKey(); err != nil {
			return err
		}
		if unsealPub == nil {
			return errors.New("no store")
		}
	}
	held, err := sp.lock(value)
	if err != nil {
		return err
	}
	if !memoryOnly {
		cryptobox, err := makeBox(unsealPub, value)
		if err == nil {
			err = writeNew(st.secretPath(name), cryptobox)
		}
		if err != nil {
			sp.free(held)
			return fmt.Errorf("not stored (%w) %q", err, name)
		}
	}
	sp.secrets[name] = held
	return nil
}

// list prints each name with + when it opens and - when it waits for unseal,
// and its state: unsealed, sealed, or memory for one never stored.
func (sp *space) list(st *store) ([]byte, error) {
	status := map[string]string{}
	for name := range sp.secrets {
		status[name] = "+ unsealed"
		if !st.holds(name) {
			status[name] = "+ memory"
		}
	}
	if st != nil {
		entries, err := os.ReadDir(st.secretsDir())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, entry := range entries {
			if _, ok := status[entry.Name()]; !ok && checkName(entry.Name()) == nil {
				status[entry.Name()] = "- sealed"
			}
		}
	}
	names, width := make([]string, 0, len(status)), 0
	for name := range status {
		names, width = append(names, name), max(width, len(name))
	}
	sort.Strings(names)
	var out bytes.Buffer
	for _, name := range names {
		mark, state, _ := strings.Cut(status[name], " ")
		fmt.Fprintf(&out, "%s %-*s  (%s)\n", mark, width, name, state)
	}
	return out.Bytes(), nil
}

func (sp *space) remove(st *store, name string) error {
	onDisk := st.holds(name)
	if onDisk {
		if err := os.Remove(st.secretPath(name)); err != nil {
			return err
		}
	}
	value, found := sp.secrets[name]
	if found {
		sp.free(value)
		delete(sp.secrets, name)
	}
	if !found && !onDisk {
		return fmt.Errorf("no such secret %q", name)
	}
	return nil
}

// seal drops the secrets the store keeps; unseal brings them back.
func (sp *space) seal(st *store) {
	for name, value := range sp.secrets {
		if st.holds(name) {
			sp.free(value)
			delete(sp.secrets, name)
		}
	}
}

// unseal checks the password against the store's public U and loads every
// cryptobox on disk that is not in memory yet; on init it sets the password.
func (sp *space) unseal(st *store, password []byte, init bool) error {
	if len(password) == 0 {
		return errors.New("empty password")
	}
	salt, unsealPub, err := st.unsealKey()
	if err != nil {
		return err
	}
	switch {
	case init && unsealPub != nil:
		return errors.New("the store already exists")
	case !init && unsealPub == nil:
		return errors.New("no store")
	case init:
		if err := st.makeDirs(); err != nil {
			return err
		}
		salt = new([32]byte)
		if _, err := rand.Read(salt[:]); err != nil {
			return err
		}
	}
	pub, priv, err := deriveU(salt, password)
	if err != nil {
		return err
	}
	defer clear(priv[:])
	if init {
		if err := writeNew(st.unsealPath(), strings.TrimSpace(encodeKey(salt))+" "+encodeKey(pub)); err != nil {
			return err
		}
		return nil
	}
	if *pub != *unsealPub {
		return errors.New("wrong password")
	}
	entries, err := os.ReadDir(st.secretsDir())
	if err != nil {
		return err
	}
	var failed []error
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := sp.secrets[name]; ok || checkName(name) != nil {
			continue
		}
		data, err := readFile(st.secretPath(name))
		if err == nil {
			var value []byte
			if value, err = openBox(data, pub, priv); err == nil {
				var held *locked
				if held, err = sp.lock(value); err == nil {
					sp.secrets[name] = held
				}
				clear(value)
			}
		}
		if err != nil {
			failed = append(failed, fmt.Errorf("%w %q", err, name))
		}
	}
	return errors.Join(failed...)
}

// deriveU computes U from the salt and the password with Argon2id and gives
// its memory back to the system at once.
var deriveU = func(salt *[32]byte, password []byte) (pub, priv *[32]byte, err error) {
	if free := memoryFree(); free < argonMemory<<10+64<<20 {
		return nil, nil, fmt.Errorf("needs %d MiB of free memory, %d MiB is free", argonMemory>>10+64, free>>20)
	}
	out := argon2.IDKey(password, salt[:], 3, argonMemory, 1, 32)
	defer debug.FreeOSMemory()
	defer clear(out)
	priv = new([32]byte)
	copy(priv[:], out)
	return publicKey(priv), priv, nil
}

// memoryFree is what the system and the service's cgroups have left.
func memoryFree() uint64 {
	free := uint64(math.MaxUint64)
	info, _ := os.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(info), "\n") {
		if kib, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			if n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(kib, "kB")), 10, 64); err == nil {
				free = n << 10
			}
		}
	}
	self, _ := os.ReadFile("/proc/self/cgroup")
	for _, line := range strings.Split(string(self), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			free = min(free, cgroupFree("/sys/fs/cgroup", path))
		}
	}
	return free
}

// cgroupFree is the least room left under memory.max from the cgroup at path
// up to root, counting inactive file cache as room the kernel gives back.
func cgroupFree(root, path string) uint64 {
	free := uint64(math.MaxUint64)
	for dir := filepath.Join(root, path); ; dir = filepath.Dir(dir) {
		limit, _ := os.ReadFile(filepath.Join(dir, "memory.max"))
		if max, err := strconv.ParseUint(strings.TrimSpace(string(limit)), 10, 64); err == nil {
			used, _ := os.ReadFile(filepath.Join(dir, "memory.current"))
			current, _ := strconv.ParseUint(strings.TrimSpace(string(used)), 10, 64)
			stat, _ := os.ReadFile(filepath.Join(dir, "memory.stat"))
			for _, line := range strings.Split(string(stat), "\n") {
				if cache, ok := strings.CutPrefix(line, "inactive_file "); ok {
					n, _ := strconv.ParseUint(cache, 10, 64)
					current -= min(current, n)
				}
			}
			free = min(free, max-min(max, current))
		}
		if dir == root || dir == filepath.Dir(dir) {
			return free
		}
	}
}

func publicKey(priv *[32]byte) *[32]byte {
	var pub [32]byte
	derived, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], derived)
	return &pub
}
