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

func add(t *testing.T, name, value string) error {
	t.Helper()
	stdin := os.Stdin
	defer func() { os.Stdin = stdin }()
	in, err := os.CreateTemp(t.TempDir(), "in")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.WriteString(value); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	os.Stdin = in
	return cmdAdd([]string{name})
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
