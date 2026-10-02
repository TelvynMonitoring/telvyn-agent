package checkpackages

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifySignedPackageTwiceAndRejectAlterations(t *testing.T) {
	base := t.TempDir()
	root, keys := filepath.Join(base, "packages"), filepath.Join(base, "keys")
	dir := filepath.Join(root, "proxmox", "1.0.0")
	for _, path := range []string{dir, keys} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	runner := []byte("print('signed')\n")
	if err := os.WriteFile(filepath.Join(dir, "runner.py"), runner, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(runner)
	manifest := Manifest{
		Name: "proxmox", Version: "1.0.0", KeyID: "release", ProtocolVersion: 1,
		Runtime: "python3", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		IsolationMode: "approved-unisolated", Checks: []string{"proxmox"},
		Files: map[string]string{"runner.py": hex.EncodeToString(digest[:])},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "release.pub"), []byte(base64.StdEncoding.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(signature), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := Verify(root, keys, "proxmox", "1.0.0", "proxmox"); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, keys, "proxmox", "1.0.0", "proxmox"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("altered signature accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(signature), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runner.py"), []byte("print('altered')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, keys, "proxmox", "1.0.0", "proxmox"); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("altered runner accepted: %v", err)
	}
}
