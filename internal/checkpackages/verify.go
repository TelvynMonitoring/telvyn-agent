// Package checkpackages verifies locally installed, administrator-approved check bundles.
// It does not download, install, or activate packages.
package checkpackages

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const maxManifestBytes = 16 << 10
const maxPackageFileBytes = 512 << 10

var slug = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var versionSlug = regexp.MustCompile(`^[0-9][a-zA-Z0-9_.-]{0,63}$`)

// Manifest is signed as its exact JSON bytes. Every package file is hashed.
type Manifest struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	KeyID           string            `json:"key_id"`
	ProtocolVersion int               `json:"protocol_version"`
	Runtime         string            `json:"runtime"`
	GOOS            string            `json:"goos"`
	GOARCH          string            `json:"goarch"`
	IsolationMode   string            `json:"isolation_mode"`
	Checks          []string          `json:"checks"`
	Files           map[string]string `json:"files"`
}

// Verify returns the runner path only after signature, compatibility, layout,
// and digest checks. Trusted keys come exclusively from a local admin path.
func Verify(root, trustedKeys, name, version, check string) (string, error) {
	if !slug.MatchString(name) || !versionSlug.MatchString(version) || !slug.MatchString(check) {
		return "", errors.New("invalid package identity")
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(trustedKeys) {
		return "", errors.New("package and trust directories must be absolute")
	}
	root = filepath.Clean(root)
	trustedKeys = filepath.Clean(trustedKeys)
	if within(root, trustedKeys) {
		return "", errors.New("trusted keys must be outside package directory")
	}
	dir := filepath.Join(root, name, version)
	for _, path := range []string{root, filepath.Join(root, name), dir, trustedKeys} {
		if err := regularPath(path, true); err != nil {
			return "", err
		}
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	raw, err := boundedFile(manifestPath, maxManifestBytes)
	if err != nil {
		return "", err
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return "", fmt.Errorf("invalid manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", errors.New("manifest has trailing data")
	}
	if manifest.Name != name || manifest.Version != version || !slug.MatchString(manifest.KeyID) ||
		manifest.ProtocolVersion != 1 || manifest.Runtime != "python3" ||
		manifest.GOOS != runtime.GOOS || manifest.GOARCH != runtime.GOARCH ||
		manifest.IsolationMode != "approved-unisolated" || len(manifest.Files) == 0 || len(manifest.Files) > 32 {
		return "", errors.New("package manifest incompatible or unsupported")
	}
	if len(manifest.Checks) == 0 || !contains(manifest.Checks, check) {
		return "", errors.New("check not declared by package")
	}
	for _, declared := range manifest.Checks {
		if !slug.MatchString(declared) {
			return "", errors.New("invalid check name in manifest")
		}
	}
	for _, entry := range []string{"manifest.json", "manifest.sig", "runner.py"} {
		if err := regularPath(filepath.Join(dir, entry), false); err != nil {
			return "", err
		}
	}
	keyRaw, err := boundedFile(filepath.Join(trustedKeys, manifest.KeyID+".pub"), 256)
	if err != nil {
		return "", err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyRaw)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return "", errors.New("invalid trusted public key")
	}
	signatureRaw, err := boundedFile(filepath.Join(dir, "manifest.sig"), 256)
	if err != nil {
		return "", err
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureRaw)))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), raw, signature) {
		return "", errors.New("package signature verification failed")
	}
	if _, ok := manifest.Files["runner.py"]; !ok {
		return "", errors.New("runner digest missing")
	}
	seen := make(map[string]bool, len(manifest.Files))
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("package symlink rejected")
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" || rel == "manifest.sig" {
			return nil
		}
		want, ok := manifest.Files[rel]
		if !ok || len(want) != 64 || (!strings.HasSuffix(rel, ".py") && !strings.HasSuffix(rel, ".txt")) {
			return errors.New("package contains undeclared or invalid file")
		}
		data, err := boundedFile(path, maxPackageFileBytes)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(digest[:]), want) {
			return errors.New("package file digest mismatch")
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(seen) != len(manifest.Files) {
		return "", errors.New("manifest declares missing package files")
	}
	for rel := range manifest.Files {
		if rel == "" || strings.Contains(rel, "\\") || filepath.IsAbs(rel) ||
			filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel))) != rel ||
			strings.HasPrefix(rel, "../") || rel == ".." {
			return "", errors.New("invalid package file path")
		}
	}
	return filepath.Join(dir, "runner.py"), nil
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func regularPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.New("package path is not a regular file or directory")
	}
	return nil
}

func boundedFile(path string, limit int64) ([]byte, error) {
	if err := regularPath(path, false); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("package file exceeds size limit")
	}
	return data, nil
}
