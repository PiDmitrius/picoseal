package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// pageScript returns the scripts of a page as a node program ending in tail.
func pageScript(t *testing.T, name, tail string) (string, string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	page, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var script strings.Builder
	script.WriteString("globalThis.self = globalThis;\n(function (module) {\n")
	for _, m := range regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(string(page), -1) {
		script.WriteString(m[1])
	}
	script.WriteString("\n" + tail + "\n})();\n")
	return node, script.String()
}

// TestExportPageCryptoboxesOpen runs the scripts of picoseal-export.html under
// node and opens the cryptoboxes they make with import.
func TestExportPageCryptoboxesOpen(t *testing.T) {
	node, script := pageScript(t, "picoseal-export.html", "process.stdout.write(makeCryptobox(process.argv[1], process.argv[2]));")

	service(t)
	key := pubkey(t)
	for text, want := range map[string]string{
		"token":                       "token",
		"trailing newline\n":          "trailing newline",
		"двe\nстроки $with `chars` ✓": "двe\nстроки $with `chars` ✓",
		strings.Repeat("x", 300):      strings.Repeat("x", 300),
	} {
		cryptobox, err := exec.Command(node, "-e", script, "--", key, text).Output()
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		got, err := importBox(t, string(cryptobox))
		if err != nil || got != want {
			t.Fatalf("%q: got %q, %v", text, got, err)
		}
	}
	for _, bad := range []string{"", "short", key + "A"} {
		if err := exec.Command(node, "-e", script, "--", bad, "token").Run(); err == nil {
			t.Fatalf("public key %q must be refused", bad)
		}
	}
	if err := exec.Command(node, "-e", script, "--", key, strings.Repeat("x", maxValue)).Run(); err != nil {
		t.Fatalf("%d bytes must go in a cryptobox: %v", maxValue, err)
	}
	if err := exec.Command(node, "-e", script, "--", key, strings.Repeat("x", maxValue)+"\n").Run(); err == nil {
		t.Fatalf("%d bytes and a newline must be refused, as export does", maxValue)
	}
}

// TestImportPageOpensCryptoboxes runs the scripts of picoseal-import.html under
// node on cryptoboxes that export makes for the page's key.
func TestImportPageOpensCryptoboxes(t *testing.T) {
	node, script := pageScript(t, "picoseal-import.html", `const keys = nacl.box.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(process.argv[1], "hex")));
try {
  process.stdout.write(encodeBase32(keys.publicKey) + "\n" + openCryptobox(keys, process.argv[2]));
} catch (e) {
  process.stdout.write(encodeBase32(keys.publicKey) + "\n" + e.message);
  process.exitCode = 1;
}`)
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(encodeKey(pub))
	open := func(with *[32]byte, cryptobox string) (string, error) {
		out, err := exec.Command(node, "-e", script, "--", hex.EncodeToString(with[:]), cryptobox).Output()
		shown, value, _ := strings.Cut(string(out), "\n")
		if with == priv && shown != key {
			t.Fatalf("page shows %q for key %q", shown, key)
		}
		return value, err
	}
	for _, value := range []string{"token", "\ufefftoken", "двe\nстроки $with `chars` ✓", strings.Repeat("x", 64), strings.Repeat("x", maxValue)} {
		cryptobox := export(t, key, value)
		if got, err := open(priv, "  "+strings.ToUpper(cryptobox)+"\n"); err != nil || got != value {
			t.Fatalf("%.20q: got %.20q, %v", value, got, err)
		}
	}
	cryptobox := export(t, key, "token")
	if got, err := open(priv, cryptobox[:60]+"\r\n"+cryptobox[60:]); err != nil || got != "token" {
		t.Fatalf("wrapped: got %q, %v", got, err)
	}
	for bad, want := range map[string]string{
		"short":         "not a cryptobox",
		cryptobox[:40]:  "not a cryptobox",
		cryptobox + "!": "not a cryptobox",
		cryptobox[:80]:  "cryptobox for another key",
	} {
		if got, err := open(priv, bad); err == nil || got != want {
			t.Fatalf("%q: got %q, %v", bad, got, err)
		}
	}
	if got, err := open(other, cryptobox); err == nil || got != errOther.Error() {
		t.Fatalf("another key: got %q, %v", got, err)
	}
	raw, err := box.SealAnonymous(nil, []byte("unpadded"), pub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := open(priv, text.EncodeToString(raw)); err == nil || got != "not a cryptobox" {
		t.Fatalf("unpadded: got %q, %v", got, err)
	}
}
