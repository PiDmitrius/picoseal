package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func install(t *testing.T) {
	t.Helper()
	previous := dir
	dir = t.TempDir()
	t.Cleanup(func() { dir = previous })
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureKey(); err != nil {
		t.Fatal(err)
	}
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

func add(t *testing.T, name, value string) error {
	t.Helper()
	redirect(t, &os.Stdin, value)
	return cmdAdd([]string{name})
}

func output(t *testing.T, f *os.File) string {
	t.Helper()
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRoundTrip(t *testing.T) {
	install(t)
	const secret = "line1\nline2 $with `chars`"
	if err := add(t, "brave", secret+"\n"); err != nil {
		t.Fatal(err)
	}
	got, err := unseal("brave")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestAddKeepsAnExistingSecret(t *testing.T) {
	install(t)
	if err := add(t, "brave", "first"); err != nil {
		t.Fatal(err)
	}
	if err := add(t, "brave", "second"); err == nil {
		t.Fatal("add must refuse to replace a secret")
	}
	got, err := unseal("brave")
	if err != nil || string(got) != "first" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNamesStayInsideTheStore(t *testing.T) {
	install(t)
	for _, name := range []string{"..", ".", "../key", "a/b", "Brave", ""} {
		if _, err := secretPath(name); err == nil {
			t.Fatalf("%q must be refused", name)
		}
	}
}

func TestOversizedSecretIsRefused(t *testing.T) {
	install(t)
	oversized := strings.Repeat("A", maxValue) + "\n" + "lost tail"
	if err := add(t, "big", oversized); err == nil {
		t.Fatal("an oversized secret must be refused, not truncated")
	}
}

func TestSecretFromAnotherKey(t *testing.T) {
	install(t)
	if err := add(t, "brave", "secret"); err != nil {
		t.Fatal(err)
	}
	record, err := os.ReadFile(filepath.Join(dir, "secrets", "brave"))
	if err != nil {
		t.Fatal(err)
	}
	install(t)
	if err := os.WriteFile(filepath.Join(dir, "secrets", "brave"), record, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := unseal("brave"); err == nil {
		t.Fatal("a record sealed for another key must fail")
	}
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

func TestExportRefusesAMalformedPubkey(t *testing.T) {
	for _, key := range []string{"", "not-a-key", strings.Repeat("A", 42), strings.Repeat("A", 44)} {
		redirect(t, &os.Stdin, "secret")
		if err := cmdExport([]string{key}); err == nil {
			t.Fatalf("%q must be refused", key)
		}
	}
}

func TestNestedRecordsTravelThroughTwoHosts(t *testing.T) {
	install(t)
	outer, outerKey := dir, pubkey(t)
	install(t)
	inner, innerKey := dir, pubkey(t)

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
	stored, err := unseal("brave")
	if err != nil || string(stored) != secret {
		t.Fatalf("got %q, %v; want %q", stored, err, secret)
	}
}

func TestImportRefusesJunkAndOtherKeys(t *testing.T) {
	install(t)
	record := export(t, pubkey(t), "secret")
	if _, err := importRecord(t, "not a record"); err == nil {
		t.Fatal("junk must be refused")
	}
	install(t)
	if _, err := importRecord(t, record); err == nil {
		t.Fatal("a record for another key must be refused")
	}
}
