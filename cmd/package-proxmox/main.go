// package-proxmox packages the reviewed integration with release-local integrity metadata.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"

	"github.com/ispwatch/collector/internal/checkpackages"
)

func main() {
	output := flag.String("out", "dist/integrations", "output directory")
	arch := flag.String("arch", "amd64", "target architecture")
	flag.Parse()
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	trust := filepath.Join(*output, "trust")
	must(os.MkdirAll(trust, 0755))
	must(os.WriteFile(filepath.Join(trust, "release.pub"), []byte(base64.StdEncoding.EncodeToString(public)), 0644))
	for _, version := range []string{"0.1.0", "0.1.2"} {
		dir := filepath.Join(*output, "packages", "virtualization", version)
		manifest := checkpackages.Manifest{Name: "virtualization", Version: version, KeyID: "release", ProtocolVersion: 1, Runtime: "python3", GOOS: "linux", GOARCH: *arch, IsolationMode: "approved-unisolated", Checks: []string{"proxmox"}, Files: map[string]string{}}
		for _, file := range []string{"runner.py", "common.py", "proxmox/check.py", "proxmox/__init__.py"} {
			data, err := os.ReadFile(filepath.Join("integrations", file))
			must(err)
			sum := sha256.Sum256(data)
			manifest.Files[file] = hex.EncodeToString(sum[:])
			dest := filepath.Join(dir, file)
			must(os.MkdirAll(filepath.Dir(dest), 0755))
			must(os.WriteFile(dest, data, 0644))
		}
		data, err := json.Marshal(manifest)
		must(err)
		must(os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0644))
		must(os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, data))), 0644))
	}
}
