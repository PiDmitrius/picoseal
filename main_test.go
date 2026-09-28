package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// service starts a service on a fresh socket and store and makes the test's
// own uid its root.
func service(t *testing.T) (string, *server) {
	t.Helper()
	return serviceFor(t, os.Getuid())
}

// userService runs the test as a user of the service rather than its root.
func userService(t *testing.T) (string, *server) {
	t.Helper()
	return serviceFor(t, os.Getuid()+1)
}

func serviceFor(t *testing.T, root int) (string, *server) {
	t.Helper()
	previousBase, previousSock := base, sockPath
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base, sockPath = dir, filepath.Join(dir, "sock")
	deriveU = func(salt *[32]byte, password []byte) (pub, priv *[32]byte, err error) {
		priv = new([32]byte)
		copy(priv[:], argon2.IDKey(password, salt[:], 1, 64, 1, 32))
		return publicKey(priv), priv, nil
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(root)
	go s.listen(listener)
	t.Cleanup(func() {
		listener.Close()
		base, sockPath = previousBase, previousSock
	})
	return sockPath, s
}

func rootStore() store {
	return store{base}
}

func redirect(t *testing.T, std **os.File, content string) *os.File {
	t.Helper()
	previous := *std
	t.Cleanup(func() { *std = previous })
	f, err := os.CreateTemp(t.TempDir(), "std")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	*std = f
	return f
}

func output(t *testing.T, f *os.File) string {
	t.Helper()
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// run gives input to the client as stdin and runs it in root's space.
func run(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	redirect(t, &os.Stdin, input)
	out := redirect(t, &os.Stdout, "")
	err := remote(args, args[0])
	return output(t, out), err
}

func save(t *testing.T, name, value string) error {
	t.Helper()
	_, err := run(t, value, "save", name)
	return err
}

func add(t *testing.T, name, value string) error {
	t.Helper()
	_, err := run(t, value, "add", name)
	return err
}

func open(t *testing.T, name string) (string, error) {
	t.Helper()
	return run(t, "", "open", name)
}

func list(t *testing.T) string {
	t.Helper()
	out, err := run(t, "", "list")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func pubkey(t *testing.T) string {
	t.Helper()
	out, err := run(t, "", "pubkey")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

func export(t *testing.T, key, value string) string {
	t.Helper()
	out := redirect(t, &os.Stdout, "")
	redirect(t, &os.Stdin, value)
	if err := cmdExport([]string{key}); err != nil {
		t.Fatal(err)
	}
	return output(t, out)
}

func importBox(t *testing.T, cryptobox string) (string, error) {
	t.Helper()
	return run(t, cryptobox, "import")
}

func seal(t *testing.T) {
	t.Helper()
	if _, err := run(t, "", "seal"); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, name string) error {
	t.Helper()
	_, err := run(t, "", "remove", name)
	return err
}

// unseal runs init or unseal with a piped password.
func unseal(t *testing.T, command, password string) error {
	t.Helper()
	_, err := run(t, password, command)
	return err
}

func TestMemoryRoundTrip(t *testing.T) {
	service(t)
	const secret = "line1\nline2 $with `chars`"
	if err := save(t, "brave", secret); err == nil || err.Error() != "no store" {
		t.Fatalf("save without a store must say so, got %v", err)
	}
	if err := add(t, "brave", secret+"\n"); err != nil {
		t.Fatal(err)
	}
	if got, err := open(t, "brave"); err != nil || got != secret {
		t.Fatalf("got %q, %v", got, err)
	}
	if got := list(t); got != "+ brave  (memory)\n" {
		t.Fatalf("list: %q", got)
	}
	if err := add(t, "brave", "second"); err == nil {
		t.Fatal("add must refuse to replace a secret")
	}
	if err := remove(t, "brave"); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, "brave"); err == nil {
		t.Fatal("a removed secret must be gone")
	}
	if _, err := os.Stat(rootStore().secretsDir()); !os.IsNotExist(err) {
		t.Fatal("memory only must write nothing to disk")
	}
}

func TestSpacesFollowTheKernelUID(t *testing.T) {
	s := newServer(0)
	if _, err := s.do(1000, false, "list", "-", nil); err == nil || err.Error() != errRoot.Error() {
		t.Fatalf("a user without --user must be sent to sudo, got %v", err)
	}
	if _, err := s.do(0, true, "list", "-", nil); err == nil {
		t.Fatal("root must refuse --user")
	}
	previous := base
	base = t.TempDir()
	defer func() { base = previous }()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.do(1000, true, "add", "brave", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.do(1001, true, "open", "brave", nil); err == nil {
		t.Fatal("another uid must not see the secret")
	}
	if _, err := s.do(1000, true, "open", "../brave", nil); err == nil {
		t.Fatal("a bad name must be refused")
	}
}

func TestSealDropsOnlyStoredSecrets(t *testing.T) {
	service(t)
	key := pubkey(t)
	if err := unseal(t, "init", "pass"); err != nil {
		t.Fatal(err)
	}
	if err := save(t, "stored", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := add(t, "brave", "secret"); err != nil {
		t.Fatal(err)
	}
	seal(t)
	if _, err := open(t, "stored"); err == nil {
		t.Fatal("seal must drop the stored secrets")
	}
	if got, err := open(t, "brave"); err != nil || got != "secret" {
		t.Fatalf("seal must keep a secret only in memory, got %q, %v", got, err)
	}
	if pubkey(t) != key {
		t.Fatal("seal must keep the session key")
	}
}

func TestStoreReloadsOnUnseal(t *testing.T) {
	service(t)
	if err := unseal(t, "unseal", "pass"); err == nil || err.Error() != "no store" {
		t.Fatalf("unseal without a store must say so, got %v", err)
	}
	if err := unseal(t, "init", "pass\n"); err != nil {
		t.Fatal(err)
	}
	if salt, pub, err := rootStore().unsealKey(); err != nil || salt == nil || pub == nil {
		t.Fatalf("init must write the salt and U, got %v", err)
	}
	if err := unseal(t, "init", "other"); err == nil || !strings.Contains(err.Error(), "the store already exists") {
		t.Fatalf("init must refuse an existing store, got %v", err)
	}
	if err := save(t, "brave", "secret"); err != nil {
		t.Fatal(err)
	}
	seal(t)
	if _, err := open(t, "brave"); err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("a sealed secret must ask for unseal, got %v", err)
	}
	if got := list(t); got != "- brave  (sealed)\n" {
		t.Fatalf("list: %q", got)
	}
	if err := save(t, "gitlab", "token"); err != nil {
		t.Fatal(err)
	}
	if err := unseal(t, "unseal", "wrong"); err == nil {
		t.Fatal("a wrong password must be refused")
	}
	if err := unseal(t, "unseal", "pass"); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"brave": "secret", "gitlab": "token"} {
		if got, err := open(t, name); err != nil || got != want {
			t.Fatalf("%s: got %q, %v", name, got, err)
		}
	}
	if err := remove(t, "brave"); err != nil {
		t.Fatal(err)
	}
	if got := list(t); got != "+ gitlab  (unsealed)\n" {
		t.Fatalf("list: %q", got)
	}
}

func TestUnsealSkipsBadCryptoboxes(t *testing.T) {
	service(t)
	if err := unseal(t, "init", "pass"); err != nil {
		t.Fatal(err)
	}
	if err := save(t, "early", "before"); err != nil {
		t.Fatal(err)
	}
	st := rootStore()
	if err := os.WriteFile(st.secretPath("junk"), []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seal(t)
	if err := unseal(t, "unseal", "pass"); err == nil || !strings.Contains(err.Error(), "junk") {
		t.Fatalf("a bad cryptobox must be reported, got %v", err)
	}
	if got, err := open(t, "early"); err != nil || got != "before" {
		t.Fatalf("a good cryptobox must load past a bad one, got %q, %v", got, err)
	}
	os.Remove(st.secretPath("junk"))
	for _, leftover := range []string{"Tmp1", "Tmp2"} {
		if err := os.WriteFile(st.secretPath(leftover), []byte(export(t, pubkey(t), "x")), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(st.secretPath("Tmp2"), []byte("partial"), 0o600)
	seal(t)
	if err := unseal(t, "unseal", "pass"); err != nil {
		t.Fatal(err)
	}
	if got, err := open(t, "early"); err != nil || got != "before" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got := list(t); got != "+ early  (unsealed)\n" {
		t.Fatalf("a leftover Tmp file must not count as a secret: %q", got)
	}
}

func TestMalformedRequestIsRefused(t *testing.T) {
	service(t)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "2\x00--bogus\x00list\x00")
	conn.(*net.UnixConn).CloseWrite()
	reply, _ := io.ReadAll(conn)
	if !strings.HasPrefix(string(reply), "error ") {
		t.Fatalf("got %q", reply)
	}
}

func TestNamesStayInsideTheStore(t *testing.T) {
	for _, name := range []string{"..", ".", "../key", "a/b", "Brave", ""} {
		if err := checkName(name); err == nil {
			t.Fatalf("%q must be refused", name)
		}
	}
}

func TestOversizedSecretIsRefused(t *testing.T) {
	service(t)
	oversized := strings.Repeat("A", maxValue) + "\n" + "lost tail"
	if err := add(t, "big", oversized); err == nil {
		t.Fatal("an oversized secret must be refused, not truncated")
	}
}

func TestExportRefusesAMalformedPubkey(t *testing.T) {
	for _, key := range []string{"", "not-a-key", strings.Repeat("A", 42), strings.Repeat("A", 44)} {
		redirect(t, &os.Stdin, "secret")
		if err := cmdExport([]string{key}); err == nil {
			t.Fatalf("%q must be refused", key)
		}
	}
}

func TestNestedCryptoboxesTravelThroughTwoServices(t *testing.T) {
	outer, _ := service(t)
	outerKey := pubkey(t)
	inner, _ := service(t)
	innerKey := pubkey(t)

	const secret = "line1\nline2 $with `chars`"
	cryptobox := export(t, outerKey, export(t, innerKey, secret))

	sockPath = outer
	cryptobox, err := importBox(t, cryptobox)
	if err != nil {
		t.Fatal(err)
	}
	sockPath = inner
	got, err := importBox(t, cryptobox)
	if err != nil || got != secret {
		t.Fatalf("got %q, %v; want %q", got, err, secret)
	}
}

func TestImportRefusesJunkAndOtherKeys(t *testing.T) {
	service(t)
	if _, err := importBox(t, "not a cryptobox"); err == nil {
		t.Fatal("before pubkey there is no session key")
	}
	cryptobox := export(t, pubkey(t), "secret")
	if _, err := importBox(t, "not a cryptobox"); err == nil {
		t.Fatal("junk must be refused")
	}
	service(t)
	pubkey(t)
	if _, err := importBox(t, cryptobox); err == nil || err.Error() != "cryptobox for another key" {
		t.Fatalf("a cryptobox for another key must be refused, got %v", err)
	}
}

func TestLargestSecretTravels(t *testing.T) {
	service(t)
	secret := strings.Repeat("x", maxValue)
	cryptobox := export(t, pubkey(t), secret)
	var wrapped strings.Builder
	for line := range slices.Chunk([]byte(strings.TrimSpace(cryptobox)), 76) {
		wrapped.Write(line)
		wrapped.WriteString("\r\n")
	}
	for _, cryptobox := range []string{cryptobox, wrapped.String()} {
		if got, err := importBox(t, cryptobox); err != nil || got != secret {
			t.Fatalf("a %d-byte secret must travel: %v", maxValue, err)
		}
	}
}

func TestNoServiceIsSaidPlainly(t *testing.T) {
	previous := sockPath
	sockPath = filepath.Join(t.TempDir(), "none")
	defer func() { sockPath = previous }()
	if _, err := request([]string{"list"}, nil); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("got %v", err)
	}
}

func TestOversizedRequestIsRefused(t *testing.T) {
	service(t)
	if _, err := request([]string{"save", "big"}, []byte(strings.Repeat("A", maxValue+1))); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v", err)
	}
	if got := list(t); got != "" {
		t.Fatalf("nothing may be kept, got %q", got)
	}
}

func TestUserSpaceIsCapped(t *testing.T) {
	sp := &space{secrets: map[string]*locked{}, users: &budget{most: 1 << 30}}
	var held []*locked
	defer func() {
		for _, l := range held {
			sp.free(l)
		}
	}()
	for range userPages {
		l, err := sp.lock([]byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, l)
	}
	if _, err := sp.lock([]byte("x")); err == nil {
		t.Fatal("a user space must stop at its share of locked memory")
	}
}

func TestStoreBehindALinkIsRefused(t *testing.T) {
	service(t)
	if err := os.Symlink(t.TempDir(), rootStore().secretsDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := request([]string{"list"}, nil); err == nil || !strings.Contains(err.Error(), "not a store") {
		t.Fatalf("secrets behind a link: got %v", err)
	}
	link := filepath.Join(t.TempDir(), "store")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	base = link
	if _, err := request([]string{"list"}, nil); err == nil || !strings.Contains(err.Error(), "not a store") {
		t.Fatalf("a store behind a link: got %v", err)
	}
}

func TestIdleClientsHoldOnlyTheirOwnUID(t *testing.T) {
	_, s := userService(t)
	var idle []net.Conn
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	for range maxUIDClients {
		c, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	start := time.Now()
	_, err := request([]string{"--user", "list"}, nil)
	s.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "too many") || time.Since(start) > time.Second {
		t.Fatalf("a uid past its share of connections must be turned away at once, even while a request runs, got %v", err)
	}
	idle[0].Close()
	idle = idle[1:]
	time.Sleep(50 * time.Millisecond)
	if _, err := request([]string{"--user", "list"}, nil); err != nil {
		t.Fatalf("a freed connection must serve again: %v", err)
	}
}

func TestUsersTogetherLeaveRootRoom(t *testing.T) {
	users := &budget{most: 3}
	a := &space{secrets: map[string]*locked{}, users: users}
	b := &space{secrets: map[string]*locked{}, users: users}
	var held []*locked
	for _, sp := range []*space{a, a, b} {
		l, err := sp.lock([]byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, l)
	}
	if _, err := b.lock([]byte("x")); err == nil {
		t.Fatal("users together must stop at their share")
	}
	b.free(held[2])
	if l, err := b.lock([]byte("x")); err != nil {
		t.Fatalf("a freed page must be usable again: %v", err)
	} else {
		b.free(l)
	}
	a.free(held[0])
	a.free(held[1])
	root := &space{secrets: map[string]*locked{}}
	l, err := root.lock([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	root.free(l)
}

func TestNamesAreCheckedBeforeTheyReachTheService(t *testing.T) {
	service(t)
	if err := add(t, "-", "dash"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "a\nb", "a b"} {
		if _, err := open(t, name); err == nil || !strings.Contains(err.Error(), "name must match") {
			t.Fatalf("open %q: %v", name, err)
		}
		if err := remove(t, name); err == nil || !strings.Contains(err.Error(), "name must match") {
			t.Fatalf("remove %q: %v", name, err)
		}
	}
	if got, err := open(t, "-"); err != nil || got != "dash" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSaveRefusesANameSealedOnDisk(t *testing.T) {
	service(t)
	if err := unseal(t, "init", "pass"); err != nil {
		t.Fatal(err)
	}
	if err := save(t, "gitlab", "token"); err != nil {
		t.Fatal(err)
	}
	seal(t)
	if err := save(t, "gitlab", "other"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("got %v", err)
	}
}

func TestSyntaxIsCheckedBeforeStdin(t *testing.T) {
	previous := sockPath
	sockPath = filepath.Join(t.TempDir(), "none")
	defer func() { sockPath = previous }()
	for _, args := range [][]string{{"save", "BAD"}, {"save"}, {"unseal", "extra"}, {"init", "extra"}, {"--user", "init"}, {"--user", "save", "x"}, {"frob"}, {"open", "a", "b"}} {
		if _, err := run(t, "secret", args...); err == nil || strings.Contains(err.Error(), "not running") {
			t.Fatalf("%v must be refused before the service is asked, got %v", args, err)
		}
	}
}

func TestWriteNewKeepsWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := writeNew(path, "first"); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(path, "second"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("got %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if data, _ := os.ReadFile(path); string(data) != "first" || len(entries) != 1 {
		t.Fatalf("got %q and %d entries", data, len(entries))
	}
}

func TestMalformedUnsealFileIsKept(t *testing.T) {
	service(t)
	st := rootStore()
	if err := st.makeDirs(); err != nil {
		t.Fatal(err)
	}
	bad := encodeKey(new([32]byte))
	if err := os.WriteFile(st.unsealPath(), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"init", "unseal"} {
		if err := unseal(t, command, "pass"); err == nil || !strings.Contains(err.Error(), "not an unseal file") {
			t.Fatalf("%s: got %v", command, err)
		}
	}
	if data, _ := os.ReadFile(st.unsealPath()); string(data) != bad {
		t.Fatal("a malformed unseal file must stay as it is")
	}
	if err := add(t, "temp", "value"); err != nil {
		t.Fatalf("add needs no store, got %v", err)
	}
}

func TestAddStaysInMemory(t *testing.T) {
	service(t)
	if _, err := run(t, "early", "add", "early"); err != nil {
		t.Fatal(err)
	}
	if err := unseal(t, "init", "pass"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "late", "add", "late"); err != nil {
		t.Fatal(err)
	}
	if err := save(t, "kept", "value"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "other", "add", "kept"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("add must refuse an existing name, got %v", err)
	}
	if got := list(t); got != "+ early  (memory)\n+ kept   (unsealed)\n+ late   (memory)\n" {
		t.Fatalf("list: %q", got)
	}
	if got, err := open(t, "late"); err != nil || got != "late" {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := unseal(t, "unseal", "pass"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(rootStore().secretsDir()); len(entries) != 1 || entries[0].Name() != "kept" {
		t.Fatalf("only save may write to disk, got %v", entries)
	}
	seal(t)
	if got := list(t); got != "+ early  (memory)\n- kept   (sealed)\n+ late   (memory)\n" {
		t.Fatalf("list: %q", got)
	}
}

func TestCgroupFreeTakesTheTightestLevel(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "system.slice", "picoseal.service")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("max\n"), 0o644)
	if got := cgroupFree(root, "/system.slice/picoseal.service"); got != math.MaxUint64 {
		t.Fatalf("no limit, got %d", got)
	}
	slice := filepath.Join(root, "system.slice")
	os.WriteFile(filepath.Join(slice, "memory.max"), []byte("1000\n"), 0o644)
	os.WriteFile(filepath.Join(slice, "memory.current"), []byte("300\n"), 0o644)
	if got := cgroupFree(root, "/system.slice/picoseal.service"); got != 700 {
		t.Fatalf("the slice's room binds, got %d", got)
	}
	os.WriteFile(filepath.Join(slice, "memory.stat"), []byte("anon 100\ninactive_file 200\n"), 0o644)
	if got := cgroupFree(root, "/system.slice/picoseal.service"); got != 900 {
		t.Fatalf("inactive file cache is room, got %d", got)
	}
	os.WriteFile(filepath.Join(slice, "memory.current"), []byte("1400\n"), 0o644)
	if got := cgroupFree(root, "/system.slice/picoseal.service"); got != 0 {
		t.Fatalf("an overfull slice leaves nothing, got %d", got)
	}
}

func TestStoreNeedsNoDirectoryUntilInit(t *testing.T) {
	service(t)
	base = filepath.Join(base, "etc")
	if err := add(t, "temp", "temp"); err != nil {
		t.Fatal(err)
	}
	if err := save(t, "kept", "value"); err == nil {
		t.Fatal("save without a store must fail")
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatal("memory only must create nothing")
	}
	if err := unseal(t, "init", "pass"); err != nil {
		t.Fatal(err)
	}
	if err := save(t, "kept", "value"); err != nil {
		t.Fatal(err)
	}
	seal(t)
	if err := unseal(t, "unseal", "pass"); err != nil {
		t.Fatal(err)
	}
	if got := list(t); got != "+ kept  (unsealed)\n+ temp  (memory)\n" {
		t.Fatalf("list: %q", got)
	}
}

func TestFailedRemoveKeepsTheSecret(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	service(t)
	if err := unseal(t, "init", "pass"); err != nil {
		t.Fatal(err)
	}
	if err := save(t, "kept", "value"); err != nil {
		t.Fatal(err)
	}
	dir := rootStore().secretsDir()
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if err := remove(t, "kept"); err == nil {
		t.Fatal("remove must fail when the store refuses")
	}
	if got, err := open(t, "kept"); err != nil || got != "value" {
		t.Fatalf("a failed remove must keep the secret, got %q, %v", got, err)
	}
}

func TestSilentServiceIsSaidPlainly(t *testing.T) {
	previous := sockPath
	sockPath = filepath.Join(t.TempDir(), "sock")
	defer func() { sockPath = previous }()
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			io.Copy(io.Discard, conn)
			conn.Close()
		}
	}()
	if _, err := request([]string{"list"}, nil); err == nil || !strings.Contains(err.Error(), "stopped before it answered") {
		t.Fatalf("got %v", err)
	}
}

func TestUserSpaceStaysInMemory(t *testing.T) {
	userService(t)
	for _, command := range []string{"save", "init", "unseal", "seal"} {
		args := []string{"--user", command}
		if command == "save" {
			args = append(args, "x")
		}
		if _, err := request(args, []byte("v")); err == nil || err.Error() != "no store" {
			t.Fatalf("%s: got %v", command, err)
		}
	}
	if _, err := request([]string{"--user", "add", "x"}, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if got, err := request([]string{"--user", "list"}, nil); err != nil || string(got) != "+ x  (memory)\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 1 {
		t.Fatalf("a user's space must write nothing, got %v", entries)
	}
}
