package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keygen(t *testing.T) string {
	t.Helper()
	previous := keyDirPath
	keyDirPath = t.TempDir()
	t.Cleanup(func() { keyDirPath = previous })
	if err := cmdKeygen(nil); err != nil {
		t.Fatal(err)
	}
	return keyDirPath
}

func wrapTo(t *testing.T, value, path string) {
	t.Helper()
	stdin, stdout := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = stdin, stdout }()

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
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	os.Stdin, os.Stdout = in, out
	if err := cmdWrap(nil); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	dir := keygen(t)
	const secret = "line1\nline2 $with `chars`"
	record := filepath.Join(dir, "record")
	wrapTo(t, secret+"\n", record)

	got, err := unseal(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestOversizedSecretIsRefused(t *testing.T) {
	dir := keygen(t)
	oversized := make([]byte, maxValue+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	oversized[maxValue] = '\n'

	stdin := os.Stdin
	defer func() { os.Stdin = stdin }()
	in, err := os.CreateTemp(dir, "in")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Write(append(oversized, []byte("lost tail")...)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	os.Stdin = in
	if _, err := readSecret(); err == nil {
		t.Fatal("expected an oversized secret to be refused, not truncated")
	}
}

func TestRecordFromAnotherKey(t *testing.T) {
	first := keygen(t)
	record := filepath.Join(first, "record")
	wrapTo(t, "secret", record)

	keygen(t)
	if _, err := unseal(record); err == nil {
		t.Fatal("expected a record sealed for another key to fail")
	}
}

func TestShortRecordIsNotAKeyMismatch(t *testing.T) {
	dir := keygen(t)
	record := filepath.Join(dir, "empty")
	if err := os.WriteFile(record, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := unseal(record)
	if err == nil || !strings.Contains(err.Error(), "not a picoseal record") {
		t.Fatalf("got %v", err)
	}
}

func TestEnvArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--", "/bin/true"},
		{"T=/tmp/record"},
		{"T=/tmp/record", "--"},
		{"bad name=/tmp/record", "--", "/bin/true"},
		{"T", "--", "/bin/true"},
	} {
		if err := cmdEnv(args); err == nil {
			t.Fatalf("%v: expected an error", args)
		}
	}
	err := cmdEnv([]string{"T=/nonexistent", "--", "true"})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("a relative command must be refused: %v", err)
	}
}

func TestWithoutDropsStaleEntries(t *testing.T) {
	got := without([]string{"T=old", "OTHER=x", "T=older"}, "T")
	if len(got) != 1 || got[0] != "OTHER=x" {
		t.Fatalf("got %v", got)
	}
}
