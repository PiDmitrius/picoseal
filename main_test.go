package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// namespace points the commands at a fresh directory, a store if store is set,
// and drops its segments afterwards.
func namespace(t *testing.T, store bool) string {
	t.Helper()
	previous := dir
	dir = t.TempDir()
	argonMemory = 64
	ns := dir
	t.Cleanup(func() {
		dir = ns
		cmdSeal(nil)
		if id, _, err := findSegment(segmentKey('E', "")); err == nil {
			removeSegment(id)
		}
		dir = previous
	})
	if store {
		if err := cmdInstall(nil); err != nil {
			t.Fatal(err)
		}
	}
	return ns
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

func add(t *testing.T, name, value string) error {
	t.Helper()
	redirect(t, &os.Stdin, value)
	return cmdAdd([]string{name})
}

func open(t *testing.T, name string) (string, error) {
	t.Helper()
	out := redirect(t, &os.Stdout, "")
	err := cmdOpen([]string{name})
	return output(t, out), err
}

func list(t *testing.T) string {
	t.Helper()
	out := redirect(t, &os.Stdout, "")
	if err := cmdList(nil); err != nil {
		t.Fatal(err)
	}
	return output(t, out)
}

func pubkey(t *testing.T) string {
	t.Helper()
	out := redirect(t, &os.Stdout, "")
	if err := cmdPubkey(nil); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(output(t, out))
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

func importRecord(t *testing.T, record string) (string, error) {
	t.Helper()
	out := redirect(t, &os.Stdout, "")
	redirect(t, &os.Stdin, record)
	err := cmdImport(nil)
	return output(t, out), err
}

func TestMemoryRoundTrip(t *testing.T) {
	namespace(t, false)
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
	if err := cmdRemove([]string{"brave"}); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, "brave"); err == nil {
		t.Fatal("a removed secret must be gone")
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets")); !os.IsNotExist(err) {
		t.Fatal("memory only must write nothing to disk")
	}
}

func TestSealKeepsTheSessionKey(t *testing.T) {
	namespace(t, false)
	key := pubkey(t)
	if err := add(t, "brave", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := cmdSeal(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, "brave"); err == nil {
		t.Fatal("seal must drop the slots")
	}
	if pubkey(t) != key {
		t.Fatal("seal must keep the session key")
	}
}

func TestStoreReloadsOnUnseal(t *testing.T) {
	namespace(t, true)
	if err := unseal([]byte("pass"), nil); err != nil {
		t.Fatal(err)
	}
	if err := add(t, "brave", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := cmdSeal(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, "brave"); err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("a sealed secret must ask for unseal, got %v", err)
	}
	if got := list(t); got != "brave sealed\n" {
		t.Fatalf("list: %q", got)
	}
	if err := add(t, "gitlab", "token"); err != nil {
		t.Fatal(err)
	}
	unsealPub, err := unsealKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := unseal([]byte("wrong"), unsealPub); err == nil {
		t.Fatal("a wrong password must be refused")
	}
	if err := unseal([]byte("pass"), unsealPub); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"brave": "secret", "gitlab": "token"} {
		if got, err := open(t, name); err != nil || got != want {
			t.Fatalf("%s: got %q, %v", name, got, err)
		}
	}
	if err := cmdRemove([]string{"brave"}); err != nil {
		t.Fatal(err)
	}
	if got := list(t); got != "gitlab\n" {
		t.Fatalf("list: %q", got)
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
	namespace(t, false)
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

func TestNestedRecordsTravelThroughTwoSessions(t *testing.T) {
	outer := namespace(t, false)
	outerKey := pubkey(t)
	inner := namespace(t, false)
	innerKey := pubkey(t)

	const secret = "line1\nline2 $with `chars`"
	record := export(t, outerKey, export(t, innerKey, secret))

	dir = outer
	record, err := importRecord(t, record)
	if err != nil {
		t.Fatal(err)
	}
	dir = inner
	got, err := importRecord(t, record)
	if err != nil {
		t.Fatal(err)
	}
	if err := add(t, "brave", got); err != nil {
		t.Fatal(err)
	}
	if stored, err := open(t, "brave"); err != nil || stored != secret {
		t.Fatalf("got %q, %v; want %q", stored, err, secret)
	}
}

func TestImportRefusesJunkAndOtherKeys(t *testing.T) {
	namespace(t, false)
	record := export(t, pubkey(t), "secret")
	if _, err := importRecord(t, "not a record"); err == nil {
		t.Fatal("junk must be refused")
	}
	namespace(t, false)
	pubkey(t)
	if _, err := importRecord(t, record); err == nil {
		t.Fatal("a record for another key must be refused")
	}
}

func TestDamagedSessionKeyIsReplacedOnceItsCreatorIsGone(t *testing.T) {
	if ns := os.Getenv("PICOSEAL_DAMAGE"); ns != "" {
		dir = ns
		if err := createSegment(segmentKey('E', ""), make([]byte, 44)); err != nil {
			t.Fatal(err)
		}
		return
	}
	namespace(t, false)
	if err := createSegment(segmentKey('E', ""), make([]byte, 44)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sessionKey(true); err == nil {
		t.Fatal("a session key its live creator still fills must be left alone")
	}
	id, _, _ := findSegment(segmentKey('E', ""))
	removeSegment(id)
	creator := exec.Command(os.Args[0], "-test.run=^TestDamagedSessionKeyIsReplacedOnceItsCreatorIsGone$")
	creator.Env = append(os.Environ(), "PICOSEAL_DAMAGE="+dir)
	if out, err := creator.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if pubkey(t) == "" {
		t.Fatal("a damaged session key must be replaced")
	}
}

func TestRemoveLeavesAnotherNameOnTheKey(t *testing.T) {
	namespace(t, false)
	pub, _, err := sessionKey(true)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := seal(pub, []byte("secret"))
	data := append(append(append([]byte(magicSlot), scope()...), 1), 'a')
	if err := createSegment(segmentKey('S', "b"), append(data, sealed...)); err != nil {
		t.Fatal(err)
	}
	if err := cmdRemove([]string{"b"}); err == nil {
		t.Fatal("remove must not delete a slot holding another name")
	}
	id, _, err := findSegment(segmentKey('S', "b"))
	if err != nil {
		t.Fatalf("the colliding slot must survive: %v", err)
	}
	removeSegment(id)
}

func TestFirstUnsealStoresSlotsAndSkipsBadRecords(t *testing.T) {
	namespace(t, true)
	if err := add(t, "early", "before"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath("junk"), []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unseal([]byte("pass"), nil); err == nil || !strings.Contains(err.Error(), "junk") {
		t.Fatalf("a bad record must be reported, got %v", err)
	}
	if err := add(t, "late", "after"); err != nil {
		t.Fatal(err)
	}
	os.Remove(secretPath("junk"))
	if err := cmdSeal(nil); err != nil {
		t.Fatal(err)
	}
	unsealPub, _ := unsealKey()
	if err := unseal([]byte("pass"), unsealPub); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"early": "before", "late": "after"} {
		if got, err := open(t, name); err != nil || got != want {
			t.Fatalf("%s: got %q, %v", name, got, err)
		}
	}
}

func TestLargestSecretTravels(t *testing.T) {
	namespace(t, false)
	secret := strings.Repeat("x", maxValue)
	record := export(t, pubkey(t), secret)
	var wrapped strings.Builder
	for line := range slices.Chunk([]byte(strings.TrimSpace(record)), 76) {
		wrapped.Write(line)
		wrapped.WriteString("\r\n")
	}
	for _, record := range []string{record, wrapped.String()} {
		if got, err := importRecord(t, record); err != nil || got != secret {
			t.Fatalf("a %d-byte secret must travel: %v", maxValue, err)
		}
	}
}
