package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// TestExportPageCryptoboxesOpen runs the scripts of picoseal-export.html under
// node and opens the cryptoboxes they make with import.
func TestExportPageCryptoboxesOpen(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	page, err := os.ReadFile("picoseal-export.html")
	if err != nil {
		t.Fatal(err)
	}
	var script strings.Builder
	script.WriteString("globalThis.self = globalThis;\n(function (module) {\n")
	for _, m := range regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(string(page), -1) {
		script.WriteString(m[1])
	}
	script.WriteString("\nprocess.stdout.write(makeCryptobox(process.argv[1], process.argv[2]));\n})();\n")

	namespace(t, false)
	key := pubkey(t)
	for text, want := range map[string]string{
		"token":                       "token",
		"trailing newline\n":          "trailing newline",
		"двe\nстроки $with `chars` ✓": "двe\nстроки $with `chars` ✓",
		strings.Repeat("x", 300):      strings.Repeat("x", 300),
	} {
		cryptobox, err := exec.Command(node, "-e", script.String(), key, text).Output()
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		got, err := importBox(t, string(cryptobox))
		if err != nil || got != want {
			t.Fatalf("%q: got %q, %v", text, got, err)
		}
	}
	for _, bad := range []string{"", "short", key + "A"} {
		if err := exec.Command(node, "-e", script.String(), bad, "token").Run(); err == nil {
			t.Fatalf("public key %q must be refused", bad)
		}
	}
	if err := exec.Command(node, "-e", script.String(), key, strings.Repeat("x", maxValue)).Run(); err != nil {
		t.Fatalf("%d bytes must go in a cryptobox: %v", maxValue, err)
	}
	if err := exec.Command(node, "-e", script.String(), key, strings.Repeat("x", maxValue)+"\n").Run(); err == nil {
		t.Fatalf("%d bytes and a newline must be refused, as export does", maxValue)
	}
}
