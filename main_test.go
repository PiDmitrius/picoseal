package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// service starts a service on a fresh socket and store root and points the
// commands at it as --user callers.
func service(t *testing.T) string {
	t.Helper()
	previousBase, previousSock, previousUser := base, sockPath, asUser
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base, sockPath, asUser = dir, filepath.Join(dir, "sock"), true
	deriveU = func(key *[32]byte, password []byte) (pub, priv *[32]byte, err error) {
		priv = new([32]byte)
		copy(priv[:], argon2.IDKey(password, saltFor(key), 1, 64, 1, 32))
		return publicKey(priv), priv, nil
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	go newServer().listen(listener)
	t.Cleanup(func() {
		listener.Close()
		base, sockPath, asUser = previousBase, previousSock, previousUser
	})
	return sockPath
}

func userStore() store {
	return store{filepath.Join(base, "users", strconv.Itoa(os.Getuid()))}
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

// run gives input to the client as stdin and runs it as a --user caller.
func run(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	redirect(t, &os.Stdin, input)
	out := redirect(t, &os.Stdout, "")
	err := remote(append([]string{"--user"}, args...), args[0])
	return output(t, out), err
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

func unseal(password string, confirmed bool) error {
	args := []string{"--user", "unseal"}
	if confirmed {
		args = append(args, "--confirmed")
	}
	_, err := request(args, []byte(password))
	return err
}

func TestMemoryRoundTrip(t *testing.T) {
	service(t)
	const secret = "line1\nline2 $with `chars`"
	if err := add(t, "brave", secret+"\n"); err != nil {
		t.Fatal(err)
	}
	if got, err := open(t, "brave"); err != nil || got != secret {
		t.Fatalf("got %q, %v", got, err)
	}
	if got := list(t); got != "brave\n" {
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
	if _, err := os.Stat(userStore().dir); !os.IsNotExist(err) {
		t.Fatal("memory only must write nothing to disk")
	}
}

func TestSpacesFollowTheKernelUID(t *testing.T) {
	s := newServer()
	if _, err := s.do(1000, false, "list", "-", false, nil); err == nil || err.Error() != errRoot.Error() {
		t.Fatalf("a user without --user must be sent to sudo, got %v", err)
	}
	if _, err := s.do(0, true, "list", "-", false, nil); err == nil {
		t.Fatal("root must refuse --user")
	}
	previous := base
	base = t.TempDir()
	defer func() { base = previous }()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.do(1000, true, "add", "brave", false, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.do(1001, true, "open", "brave", false, nil); err == nil {
		t.Fatal("another uid must not see the secret")
	}
	if _, err := s.do(1000, true, "open", "../brave", false, nil); err == nil {
		t.Fatal("a bad name must be refused")
	}
}

func TestSealKeepsTheSessionKey(t *testing.T) {
	service(t)
	key := pubkey(t)
	if err := add(t, "brave", "secret"); err != nil {
		t.Fatal(err)
	}
	seal(t)
	if _, err := open(t, "brave"); err == nil {
		t.Fatal("seal must drop the secrets")
	}
	if pubkey(t) != key {
		t.Fatal("seal must keep the session key")
	}
}

func TestStoreReloadsOnUnseal(t *testing.T) {
	service(t)
	if err := unseal("pass", false); err == nil || err.Error() != errConfirm.Error() {
		t.Fatalf("a new store must ask for confirmation, got %v", err)
	}
	if err := unseal("pass", true); err != nil {
		t.Fatal(err)
	}
	if err := add(t, "brave", "secret"); err != nil {
		t.Fatal(err)
	}
	seal(t)
	if _, err := open(t, "brave"); err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("a sealed secret must ask for unseal, got %v", err)
	}
	if got := list(t); got != "brave sealed\n" {
		t.Fatalf("list: %q", got)
	}
	if err := add(t, "gitlab", "token"); err != nil {
		t.Fatal(err)
	}
	if err := unseal("wrong", false); err == nil {
		t.Fatal("a wrong password must be refused")
	}
	if err := unseal("pass", false); err != nil {
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
	if got := list(t); got != "gitlab\n" {
		t.Fatalf("list: %q", got)
	}
}

func TestFirstUnsealStoresMemoryAndSkipsBadCryptoboxes(t *testing.T) {
	service(t)
	if err := add(t, "early", "before"); err != nil {
		t.Fatal(err)
	}
	st := userStore()
	if err := st.ensureKey(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.secretPath("junk"), []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unseal("pass", true); err == nil || !strings.Contains(err.Error(), "junk") {
		t.Fatalf("a bad cryptobox must be reported, got %v", err)
	}
	os.Remove(st.secretPath("junk"))
	seal(t)
	if err := unseal("pass", false); err != nil {
		t.Fatal(err)
	}
	if got, err := open(t, "early"); err != nil || got != "before" {
		t.Fatalf("got %q, %v", got, err)
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
	outer := service(t)
	outerKey := pubkey(t)
	inner := service(t)
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
	if _, err := importBox(t, cryptobox); err == nil {
		t.Fatal("a cryptobox for another key must be refused")
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
	if _, err := request([]string{"--user", "list"}, nil); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("got %v", err)
	}
}

func TestOversizedRequestIsRefused(t *testing.T) {
	service(t)
	if _, err := request([]string{"--user", "add", "big"}, []byte(strings.Repeat("A", maxValue+1))); err == nil || !strings.Contains(err.Error(), "too large") {
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
	st := userStore()
	if err := os.MkdirAll(filepath.Dir(st.dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, st.dir); err != nil {
		t.Fatal(err)
	}
	if _, err := request([]string{"--user", "list"}, nil); err == nil || !strings.Contains(err.Error(), "not a store") {
		t.Fatalf("got %v", err)
	}
}

func TestIdleClientsHoldOnlyTheirOwnUID(t *testing.T) {
	service(t)
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
	if _, err := request([]string{"--user", "list"}, nil); err == nil {
		t.Fatal("a uid past its share of connections must be turned away")
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

func TestLinkAboveTheStoreIsRefused(t *testing.T) {
	service(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "users")); err != nil {
		t.Fatal(err)
	}
	if _, err := request([]string{"--user", "list"}, nil); err == nil || !strings.Contains(err.Error(), "not a store") {
		t.Fatalf("got %v", err)
	}
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

func TestAddRefusesANameSealedOnDisk(t *testing.T) {
	service(t)
	if err := unseal("pass", true); err != nil {
		t.Fatal(err)
	}
	if err := add(t, "gitlab", "token"); err != nil {
		t.Fatal(err)
	}
	seal(t)
	if err := add(t, "gitlab", "other"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("got %v", err)
	}
}

func TestConfirmationCannotBeTyped(t *testing.T) {
	service(t)
	if _, err := run(t, "pass", "unseal", "--confirmed"); err == nil || err.Error() != errUsage.Error() {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(userStore().unsealPath()); !os.IsNotExist(err) {
		t.Fatal("a typed --confirmed must set no password")
	}
}

func TestSyntaxIsCheckedBeforeStdin(t *testing.T) {
	previous := sockPath
	sockPath = filepath.Join(t.TempDir(), "none")
	defer func() { sockPath = previous }()
	for _, args := range [][]string{{"add", "BAD"}, {"add"}, {"unseal", "extra"}, {"frob"}, {"open", "a", "b"}} {
		if _, err := run(t, "secret", args...); err == nil || strings.Contains(err.Error(), "not running") {
			t.Fatalf("%v must be refused before the service is asked, got %v", args, err)
		}
	}
}
